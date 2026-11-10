"""
Lõi mã hóa của trình quản lý mật khẩu.

Nguyên lý:
    mật khẩu chính + salt --(scrypt)--> khóa 256-bit --(AES-256-GCM)--> dữ liệu đã mã hóa

- Không lưu mật khẩu chính, không lưu khóa. File vault chỉ chứa salt, nonce và dữ liệu đã mã hóa.
- Nhập sai mật khẩu chính -> khóa sai -> AES-GCM báo lỗi xác thực -> biết là sai.
- Ai sửa file dù chỉ 1 byte -> AES-GCM cũng báo lỗi -> phát hiện file bị can thiệp.
"""
import base64
import json
import os
import secrets
import string
import tempfile

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

PHIEN_BAN = 1

# Tham số scrypt mặc định: N = 2^17, r = 8, p = 1 (theo khuyến nghị của OWASP).
# Mỗi lần tạo khóa tốn khoảng 128 MB RAM và vài trăm mili giây:
# người dùng không thấy chậm, nhưng kẻ tấn công đoán hàng tỷ mật khẩu thì rất tốn kém.
SCRYPT_N = 2 ** 17
SCRYPT_R = 8
SCRYPT_P = 1

# Giới hạn trên khi MỞ file: chặn file độc hại khai báo tham số khổng lồ
# để làm treo máy (tấn công từ chối dịch vụ).
MAX_SCRYPT_N = 2 ** 20
MAX_SCRYPT_R = 16
MAX_SCRYPT_P = 4

DO_DAI_SALT = 16      # 128 bit
DO_DAI_NONCE = 12     # 96 bit, độ dài chuẩn cho AES-GCM
DO_DAI_KHOA = 32      # 256 bit -> AES-256
MAT_KHAU_CHINH_TOI_THIEU = 8


class SaiMatKhau(Exception):
    """Mật khẩu chính sai, hoặc file vault đã bị chỉnh sửa."""


class FileVaultHong(Exception):
    """File vault sai định dạng hoặc có tham số không hợp lệ."""


def _b64(du_lieu):
    return base64.b64encode(du_lieu).decode("ascii")


def _tu_b64(chuoi):
    return base64.b64decode(chuoi.encode("ascii"), validate=True)


def tao_khoa(mat_khau, salt, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P):
    # Biến mật khẩu chính thành khóa 256-bit bằng scrypt
    kdf = Scrypt(salt=salt, length=DO_DAI_KHOA, n=n, r=r, p=p)
    return kdf.derive(mat_khau.encode("utf-8"))


def kiem_tra_mat_khau_chinh(mat_khau):
    if len(mat_khau) < MAT_KHAU_CHINH_TOI_THIEU:
        raise ValueError(f"Mật khẩu chính phải có ít nhất {MAT_KHAU_CHINH_TOI_THIEU} ký tự.")


def tao_mat_khau_ngau_nhien(do_dai=16):
    # Dùng module secrets (an toàn cho mật mã), KHÔNG dùng random.
    # Bảo đảm có đủ chữ thường, chữ hoa, chữ số và ký tự đặc biệt.
    if do_dai < 8:
        raise ValueError("Độ dài tối thiểu là 8 ký tự.")
    nhom = [string.ascii_lowercase, string.ascii_uppercase, string.digits, "!@#$%^&*()-_=+[]{}"]
    tat_ca = "".join(nhom)
    while True:
        mat_khau = "".join(secrets.choice(tat_ca) for _ in range(do_dai))
        if all(any(c in g for c in mat_khau) for g in nhom):
            return mat_khau


class Vault:
    def __init__(self, path, khoa, kdf, muc):
        self.path = path
        self._khoa = khoa
        self._kdf = kdf          # {"ten", "n", "r", "p", "salt"}: lưu công khai trong file
        self._muc = muc          # {tên dịch vụ: {"tai_khoan", "mat_khau", "ghi_chu"}}

    # ---------- Tạo mới / mở ----------
    @classmethod
    def tao_moi(cls, path, mat_khau_chinh, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P):
        kiem_tra_mat_khau_chinh(mat_khau_chinh)
        if os.path.exists(path):
            raise FileExistsError("File vault đã tồn tại.")
        salt = os.urandom(DO_DAI_SALT)
        kdf = {"ten": "scrypt", "n": n, "r": r, "p": p, "salt": _b64(salt)}
        vault = cls(path, tao_khoa(mat_khau_chinh, salt, n, r, p), kdf, {})
        vault.luu()
        return vault

    @classmethod
    def mo(cls, path, mat_khau_chinh):
        try:
            with open(path, encoding="utf-8") as f:
                noi_dung = json.load(f)
            kdf = noi_dung["kdf"]
            n, r, p = int(kdf["n"]), int(kdf["r"]), int(kdf["p"])
            salt = _tu_b64(kdf["salt"])
            nonce = _tu_b64(noi_dung["nonce"])
            ban_ma = _tu_b64(noi_dung["du_lieu"])
            phien_ban = noi_dung["phien_ban"]
        except (OSError, ValueError, KeyError, TypeError) as e:
            raise FileVaultHong(f"Không đọc được file vault: {e}") from e

        # Kiểm tra tham số TRƯỚC khi chạy scrypt
        if phien_ban != PHIEN_BAN or kdf.get("ten") != "scrypt":
            raise FileVaultHong("Phiên bản hoặc thuật toán không được hỗ trợ.")
        if not (2 <= n <= MAX_SCRYPT_N and n & (n - 1) == 0 and 1 <= r <= MAX_SCRYPT_R and 1 <= p <= MAX_SCRYPT_P):
            raise FileVaultHong("Tham số scrypt không hợp lệ hoặc quá lớn.")
        if len(salt) != DO_DAI_SALT or len(nonce) != DO_DAI_NONCE:
            raise FileVaultHong("Salt hoặc nonce sai độ dài.")

        kdf_chuan = {"ten": "scrypt", "n": n, "r": r, "p": p, "salt": _b64(salt)}
        khoa = tao_khoa(mat_khau_chinh, salt, n, r, p)
        try:
            ban_ro = AESGCM(khoa).decrypt(nonce, ban_ma, cls._aad(kdf_chuan))
        except InvalidTag:
            # Sai mật khẩu HOẶC file bị sửa: không thể (và không nên) phân biệt hai trường hợp
            raise SaiMatKhau("Sai mật khẩu chính hoặc file vault đã bị chỉnh sửa.") from None
        return cls(path, khoa, kdf_chuan, json.loads(ban_ro.decode("utf-8")))

    # ---------- Lưu ----------
    @staticmethod
    def _aad(kdf):
        # AAD (Additional Authenticated Data): phần đầu file không cần giấu nhưng phải chống sửa.
        # Nếu ai đổi salt hay tham số scrypt trong file, giải mã sẽ thất bại.
        return json.dumps({"phien_ban": PHIEN_BAN, "kdf": kdf}, sort_keys=True).encode("utf-8")

    def luu(self):
        self._dam_bao_dang_mo()
        nonce = os.urandom(DO_DAI_NONCE)   # nonce MỚI cho mỗi lần lưu, không bao giờ dùng lại
        ban_ma = AESGCM(self._khoa).encrypt(
            nonce, json.dumps(self._muc, ensure_ascii=False).encode("utf-8"), self._aad(self._kdf))
        noi_dung = {"phien_ban": PHIEN_BAN, "kdf": self._kdf, "nonce": _b64(nonce), "du_lieu": _b64(ban_ma)}

        # Ghi ra file tạm rồi thay thế: nếu mất điện giữa chừng, file cũ vẫn còn nguyên
        thu_muc = os.path.dirname(os.path.abspath(self.path))
        fd, tam = tempfile.mkstemp(dir=thu_muc, prefix=".vault-", suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(noi_dung, f)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tam, self.path)
        except BaseException:
            if os.path.exists(tam):
                os.remove(tam)
            raise

    # ---------- Thao tác với mật khẩu ----------
    def them(self, ten, tai_khoan, mat_khau, ghi_chu=""):
        self._dam_bao_dang_mo()
        ten = ten.strip()
        if not ten:
            raise ValueError("Tên dịch vụ không được để trống.")
        self._muc[ten] = {"tai_khoan": tai_khoan, "mat_khau": mat_khau, "ghi_chu": ghi_chu}
        self.luu()

    def xoa(self, ten):
        self._dam_bao_dang_mo()
        del self._muc[ten]
        self.luu()

    def lay(self, ten):
        self._dam_bao_dang_mo()
        return dict(self._muc[ten])

    def danh_sach(self):
        self._dam_bao_dang_mo()
        return sorted(self._muc)

    def doi_mat_khau_chinh(self, mat_khau_moi):
        # Tạo salt mới và khóa mới, rồi mã hóa lại toàn bộ dữ liệu
        self._dam_bao_dang_mo()
        kiem_tra_mat_khau_chinh(mat_khau_moi)
        salt = os.urandom(DO_DAI_SALT)
        n, r, p = self._kdf["n"], self._kdf["r"], self._kdf["p"]
        self._kdf = {"ten": "scrypt", "n": n, "r": r, "p": p, "salt": _b64(salt)}
        self._khoa = tao_khoa(mat_khau_moi, salt, n, r, p)
        self.luu()

    # ---------- Khóa ----------
    def khoa(self):
        # Xóa khóa và dữ liệu khỏi đối tượng. Lưu ý: Python không cho xóa hẳn
        # dữ liệu khỏi bộ nhớ, đây là giới hạn của ngôn ngữ (ghi trong SECURITY.md).
        self._khoa = None
        self._muc = {}

    @property
    def dang_mo(self):
        return self._khoa is not None

    def _dam_bao_dang_mo(self):
        if self._khoa is None:
            raise RuntimeError("Vault đã bị khóa, hãy mở lại bằng mật khẩu chính.")