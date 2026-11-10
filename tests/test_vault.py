"""
Kiểm thử lõi mã hóa: chứng minh các tính chất bảo mật hoạt động đúng.

Chạy: python -m unittest discover tests -v
"""
import base64
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from password_manager.vault import (  # noqa: E402
    FileVaultHong, SaiMatKhau, Vault, tao_mat_khau_ngau_nhien,
)

MAT_KHAU = "mat-khau-chinh-123"
N_NHANH = 2 ** 14   # tham số scrypt nhỏ hơn để test chạy nhanh (chỉ dùng trong test)


class TestVault(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.tmp.name, "test.vault")
        self.vault = Vault.tao_moi(self.path, MAT_KHAU, n=N_NHANH)
        self.vault.them("Gmail", "kimanh@gmail.com", "Abc!12345", "tài khoản chính")

    def tearDown(self):
        self.tmp.cleanup()

    def doc_file(self):
        with open(self.path, encoding="utf-8") as f:
            return json.load(f)

    def ghi_file(self, noi_dung):
        with open(self.path, "w", encoding="utf-8") as f:
            json.dump(noi_dung, f)

    # ---------- Chức năng cơ bản ----------
    def test_mo_lai_dung_mat_khau(self):
        v = Vault.mo(self.path, MAT_KHAU)
        self.assertEqual(v.lay("Gmail")["mat_khau"], "Abc!12345")
        self.assertEqual(v.lay("Gmail")["ghi_chu"], "tài khoản chính")

    def test_them_sua_xoa(self):
        self.vault.them("Facebook", "ka", "mk1")
        self.vault.them("Facebook", "ka", "mk2")          # thêm trùng tên = sửa
        self.assertEqual(Vault.mo(self.path, MAT_KHAU).lay("Facebook")["mat_khau"], "mk2")
        self.vault.xoa("Facebook")
        self.assertEqual(Vault.mo(self.path, MAT_KHAU).danh_sach(), ["Gmail"])

    def test_tham_so_mac_dinh_hoat_dong(self):
        path = os.path.join(self.tmp.name, "mac_dinh.vault")
        Vault.tao_moi(path, MAT_KHAU)
        self.assertEqual(Vault.mo(path, MAT_KHAU).danh_sach(), [])

    # ---------- Bảo mật ----------
    def test_sai_mat_khau_bi_tu_choi(self):
        with self.assertRaises(SaiMatKhau):
            Vault.mo(self.path, "mat-khau-sai-123")

    def test_file_khong_chua_ban_ro(self):
        with open(self.path, encoding="utf-8") as f:
            noi_dung = f.read()
        for bi_mat in ("Gmail", "kimanh@gmail.com", "Abc!12345", MAT_KHAU):
            self.assertNotIn(bi_mat, noi_dung)

    def test_phat_hien_du_lieu_bi_sua(self):
        noi_dung = self.doc_file()
        ban_ma = bytearray(base64.b64decode(noi_dung["du_lieu"]))
        ban_ma[0] ^= 1                                     # lật 1 bit
        noi_dung["du_lieu"] = base64.b64encode(ban_ma).decode()
        self.ghi_file(noi_dung)
        with self.assertRaises(SaiMatKhau):
            Vault.mo(self.path, MAT_KHAU)

    def test_phat_hien_salt_bi_sua(self):
        # Salt nằm trong AAD nên sửa salt cũng bị phát hiện
        noi_dung = self.doc_file()
        noi_dung["kdf"]["salt"] = base64.b64encode(os.urandom(16)).decode()
        self.ghi_file(noi_dung)
        with self.assertRaises(SaiMatKhau):
            Vault.mo(self.path, MAT_KHAU)

    def test_chan_tham_so_scrypt_qua_lon(self):
        # File độc hại khai báo N = 2^30 để làm treo máy: phải bị chặn TRƯỚC khi chạy scrypt
        noi_dung = self.doc_file()
        noi_dung["kdf"]["n"] = 2 ** 30
        self.ghi_file(noi_dung)
        with self.assertRaises(FileVaultHong):
            Vault.mo(self.path, MAT_KHAU)

    def test_chan_tham_so_scrypt_sai(self):
        noi_dung = self.doc_file()
        noi_dung["kdf"]["n"] = 1000                        # không phải lũy thừa của 2
        self.ghi_file(noi_dung)
        with self.assertRaises(FileVaultHong):
            Vault.mo(self.path, MAT_KHAU)

    def test_file_hong(self):
        with open(self.path, "w", encoding="utf-8") as f:
            f.write("day khong phai json")
        with self.assertRaises(FileVaultHong):
            Vault.mo(self.path, MAT_KHAU)

    def test_nonce_moi_moi_lan_luu(self):
        nonce_1 = self.doc_file()["nonce"]
        self.vault.luu()
        nonce_2 = self.doc_file()["nonce"]
        self.assertNotEqual(nonce_1, nonce_2)

    def test_doi_mat_khau_chinh(self):
        salt_cu = self.doc_file()["kdf"]["salt"]
        self.vault.doi_mat_khau_chinh("mat-khau-moi-456")
        self.assertNotEqual(self.doc_file()["kdf"]["salt"], salt_cu)   # salt mới
        with self.assertRaises(SaiMatKhau):
            Vault.mo(self.path, MAT_KHAU)                               # mật khẩu cũ hết dùng được
        self.assertEqual(Vault.mo(self.path, "mat-khau-moi-456").danh_sach(), ["Gmail"])

    def test_khoa_vault(self):
        self.vault.khoa()
        self.assertFalse(self.vault.dang_mo)
        with self.assertRaises(RuntimeError):
            self.vault.lay("Gmail")

    def test_mat_khau_chinh_qua_ngan(self):
        with self.assertRaises(ValueError):
            Vault.tao_moi(os.path.join(self.tmp.name, "ngan.vault"), "1234567", n=N_NHANH)

    def test_khong_ghi_de_vault_co_san(self):
        with self.assertRaises(FileExistsError):
            Vault.tao_moi(self.path, MAT_KHAU, n=N_NHANH)

    def test_khong_de_lai_file_tam(self):
        self.vault.luu()
        self.assertEqual(os.listdir(self.tmp.name), ["test.vault"])


class TestTaoMatKhau(unittest.TestCase):
    def test_do_dai_va_du_loai_ky_tu(self):
        for _ in range(50):
            mk = tao_mat_khau_ngau_nhien(16)
            self.assertEqual(len(mk), 16)
            self.assertTrue(any(c.islower() for c in mk))
            self.assertTrue(any(c.isupper() for c in mk))
            self.assertTrue(any(c.isdigit() for c in mk))
            self.assertTrue(any(not c.isalnum() for c in mk))

    def test_khong_trung_lap(self):
        self.assertEqual(len({tao_mat_khau_ngau_nhien() for _ in range(200)}), 200)

    def test_tu_choi_do_dai_qua_ngan(self):
        with self.assertRaises(ValueError):
            tao_mat_khau_ngau_nhien(4)


if __name__ == "__main__":
    unittest.main()