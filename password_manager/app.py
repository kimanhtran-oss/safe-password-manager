"""
Giao diện Tkinter cho trình quản lý mật khẩu.

Tính năng bảo mật ở tầng giao diện:
- Mật khẩu luôn hiển thị dạng •••• cho tới khi bấm "Hiện".
- Sao chép mật khẩu: clipboard tự xóa sau 20 giây.
- Tự khóa vault sau 5 phút không thao tác.
- Nhập sai mật khẩu chính 5 lần: phải chờ, mỗi lần sai thêm thời gian chờ gấp đôi.
"""
import os
import time
import tkinter as tk
from tkinter import messagebox, ttk

from password_manager.vault import FileVaultHong, SaiMatKhau, Vault, tao_mat_khau_ngau_nhien

THU_MUC_DU_LIEU = os.path.join(os.path.expanduser("~"), ".safe-password-manager")
FILE_VAULT = os.path.join(THU_MUC_DU_LIEU, "my.vault")

TU_KHOA_SAU_GIAY = 5 * 60
XOA_CLIPBOARD_SAU_GIAY = 20
SO_LAN_SAI_CHO_PHEP = 5
THOI_GIAN_CHO_GOC = 30            # giây, nhân đôi sau mỗi lần sai tiếp theo
MAT_KHAU_CHINH_KHUYEN_NGHI = 12
AN = "••••••••"


class App:
    def __init__(self, root, path=FILE_VAULT):
        self.root = root
        self.path = path
        self.vault = None
        self._ten_dang_chon = None
        self._hien_mat_khau = False
        self._hen_khoa = None
        self._hen_clipboard = None
        self._noi_dung_clipboard = None
        self._so_lan_sai = 0
        self._khoa_den = 0.0
        self._cua_so_con = []

        root.title("Safe Password Manager")
        root.geometry("760x460")
        root.minsize(640, 400)
        root.protocol("WM_DELETE_WINDOW", self.thoat)
        # Mọi thao tác phím/chuột đều đặt lại đồng hồ tự khóa
        root.bind_all("<KeyPress>", self._co_hoat_dong, add="+")
        root.bind_all("<ButtonPress>", self._co_hoat_dong, add="+")

        self.khung = ttk.Frame(root, padding=16)
        self.khung.pack(fill="both", expand=True)
        self.man_hinh_dang_nhap()

    # ================= Tiện ích =================
    def _xoa_khung(self):
        for w in self.khung.winfo_children():
            w.destroy()

    def _co_hoat_dong(self, _event=None):
        if self.vault is not None:
            self._dat_hen_khoa()

    def _dat_hen_khoa(self):
        if self._hen_khoa is not None:
            self.root.after_cancel(self._hen_khoa)
        self._hen_khoa = self.root.after(TU_KHOA_SAU_GIAY * 1000, self._tu_khoa)

    def _o_mat_khau(self, parent):
        bien = tk.StringVar()
        o = ttk.Entry(parent, textvariable=bien, show="•", width=32)
        return bien, o

    # ================= Màn hình đăng nhập =================
    def man_hinh_dang_nhap(self, thong_bao=""):
        self._xoa_khung()
        tao_moi = not os.path.exists(self.path)

        ttk.Label(self.khung, text="🔐 Safe Password Manager", font=("Segoe UI", 18, "bold")).pack(pady=(30, 4))
        ttk.Label(self.khung, text="Tạo vault mới" if tao_moi else "Mở vault của bạn").pack(pady=(0, 16))
        if thong_bao:
            ttk.Label(self.khung, text=thong_bao, foreground="#b45309").pack(pady=(0, 8))

        form = ttk.Frame(self.khung)
        form.pack()
        ttk.Label(form, text="Mật khẩu chính:").grid(row=0, column=0, sticky="w", pady=4)
        self.bien_mk, o_mk = self._o_mat_khau(form)
        o_mk.grid(row=0, column=1, pady=4)
        o_mk.focus_set()

        if tao_moi:
            ttk.Label(form, text="Nhập lại:").grid(row=1, column=0, sticky="w", pady=4)
            self.bien_mk2, o_mk2 = self._o_mat_khau(form)
            o_mk2.grid(row=1, column=1, pady=4)
            ttk.Label(form, text=f"Nên dùng ít nhất {MAT_KHAU_CHINH_KHUYEN_NGHI} ký tự. "
                                 "Quên mật khẩu chính là mất toàn bộ dữ liệu.",
                      foreground="#6b7280").grid(row=2, column=0, columnspan=2, pady=(4, 0))
            ttk.Button(self.khung, text="Tạo vault", command=self._tao_vault).pack(pady=12)
            o_mk2.bind("<Return>", lambda e: self._tao_vault())
        else:
            ttk.Button(self.khung, text="Mở khóa", command=self._mo_vault).pack(pady=12)
            o_mk.bind("<Return>", lambda e: self._mo_vault())

    def _tao_vault(self):
        mk, mk2 = self.bien_mk.get(), self.bien_mk2.get()
        if mk != mk2:
            messagebox.showerror("Lỗi", "Hai mật khẩu không khớp.")
            return
        if len(mk) < MAT_KHAU_CHINH_KHUYEN_NGHI and not messagebox.askyesno(
                "Mật khẩu ngắn", f"Mật khẩu chính dưới {MAT_KHAU_CHINH_KHUYEN_NGHI} ký tự dễ bị đoán hơn. "
                                 "Vẫn tiếp tục?"):
            return
        try:
            os.makedirs(os.path.dirname(os.path.abspath(self.path)), exist_ok=True)
            self.root.config(cursor="watch")
            self.root.update_idletasks()
            self.vault = Vault.tao_moi(self.path, mk)
        except (ValueError, FileExistsError, OSError) as e:
            messagebox.showerror("Lỗi", str(e))
            return
        finally:
            self.root.config(cursor="")
        self._vao_man_hinh_chinh()

    def _mo_vault(self):
        con_lai = self._khoa_den - time.monotonic()
        if con_lai > 0:
            messagebox.showwarning("Tạm khóa", f"Nhập sai quá nhiều lần. Thử lại sau {int(con_lai) + 1} giây.")
            return
        try:
            self.root.config(cursor="watch")
            self.root.update_idletasks()
            self.vault = Vault.mo(self.path, self.bien_mk.get())
        except SaiMatKhau:
            self._so_lan_sai += 1
            self.bien_mk.set("")
            if self._so_lan_sai >= SO_LAN_SAI_CHO_PHEP:
                cho = THOI_GIAN_CHO_GOC * 2 ** (self._so_lan_sai - SO_LAN_SAI_CHO_PHEP)
                self._khoa_den = time.monotonic() + cho
                messagebox.showerror("Sai mật khẩu", f"Sai {self._so_lan_sai} lần. Tạm khóa {cho} giây.")
            else:
                messagebox.showerror("Sai mật khẩu", f"Sai mật khẩu chính "
                                     f"(còn {SO_LAN_SAI_CHO_PHEP - self._so_lan_sai} lần trước khi bị tạm khóa).")
            return
        except FileVaultHong as e:
            messagebox.showerror("File vault lỗi", str(e))
            return
        finally:
            self.root.config(cursor="")
        self._so_lan_sai = 0
        self._vao_man_hinh_chinh()

    # ================= Màn hình chính =================
    def _vao_man_hinh_chinh(self):
        self._ten_dang_chon = None
        self._dat_hen_khoa()
        self.man_hinh_chinh()

    def man_hinh_chinh(self):
        self._xoa_khung()

        thanh = ttk.Frame(self.khung)
        thanh.pack(fill="x", pady=(0, 10))
        ttk.Label(thanh, text="Tìm:").pack(side="left")
        self.bien_tim = tk.StringVar()
        self.bien_tim.trace_add("write", lambda *a: self._cap_nhat_danh_sach())
        ttk.Entry(thanh, textvariable=self.bien_tim, width=24).pack(side="left", padx=(4, 12))
        ttk.Button(thanh, text="🔒 Khóa", command=self.khoa).pack(side="right")
        ttk.Button(thanh, text="Đổi mật khẩu chính", command=self._hop_doi_mat_khau_chinh).pack(side="right", padx=4)
        ttk.Button(thanh, text="+ Thêm", command=lambda: self._hop_sua(None)).pack(side="right")

        than = ttk.Frame(self.khung)
        than.pack(fill="both", expand=True)
        self.ds = tk.Listbox(than, width=28, exportselection=False)
        self.ds.pack(side="left", fill="y")
        self.ds.bind("<<ListboxSelect>>", self._chon_muc)

        self.chi_tiet = ttk.Frame(than, padding=(16, 0))
        self.chi_tiet.pack(side="left", fill="both", expand=True)

        self.trang_thai = ttk.Label(self.khung, text="", foreground="#047857")
        self.trang_thai.pack(fill="x", pady=(8, 0))

        self._cap_nhat_danh_sach()
        self._hien_chi_tiet()

    def _cap_nhat_danh_sach(self):
        if self.vault is None:
            return
        tu_khoa = self.bien_tim.get().strip().lower()
        self._ten_hien = [t for t in self.vault.danh_sach() if tu_khoa in t.lower()]
        self.ds.delete(0, "end")
        for t in self._ten_hien:
            self.ds.insert("end", t)
        if self._ten_dang_chon in self._ten_hien:
            i = self._ten_hien.index(self._ten_dang_chon)
            self.ds.selection_set(i)
            self.ds.see(i)

    def _chon_muc(self, _event=None):
        chon = self.ds.curselection()
        if not chon:
            return
        self._ten_dang_chon = self._ten_hien[chon[0]]
        self._hien_mat_khau = False
        self._hien_chi_tiet()

    def _hien_chi_tiet(self):
        for w in self.chi_tiet.winfo_children():
            w.destroy()
        if self.vault is None or self._ten_dang_chon is None:
            so = len(self.vault.danh_sach()) if self.vault else 0
            ttk.Label(self.chi_tiet, text=f"{so} mục đã lưu.\nChọn một mục bên trái hoặc bấm “+ Thêm”.",
                      foreground="#6b7280").pack(anchor="w", pady=20)
            return

        muc = self.vault.lay(self._ten_dang_chon)
        ttk.Label(self.chi_tiet, text=self._ten_dang_chon, font=("Segoe UI", 14, "bold")).grid(
            row=0, column=0, columnspan=3, sticky="w", pady=(0, 12))

        ttk.Label(self.chi_tiet, text="Tài khoản:").grid(row=1, column=0, sticky="w", pady=4)
        ttk.Label(self.chi_tiet, text=muc["tai_khoan"]).grid(row=1, column=1, sticky="w", padx=8)
        ttk.Button(self.chi_tiet, text="Sao chép",
                   command=lambda: self._sao_chep(muc["tai_khoan"], "tài khoản")).grid(row=1, column=2)

        ttk.Label(self.chi_tiet, text="Mật khẩu:").grid(row=2, column=0, sticky="w", pady=4)
        ttk.Label(self.chi_tiet, text=muc["mat_khau"] if self._hien_mat_khau else AN,
                  font=("Consolas", 11)).grid(row=2, column=1, sticky="w", padx=8)
        nut = ttk.Frame(self.chi_tiet)
        nut.grid(row=2, column=2)
        ttk.Button(nut, text="Ẩn" if self._hien_mat_khau else "Hiện", command=self._bat_tat_hien).pack(side="left")
        ttk.Button(nut, text="Sao chép",
                   command=lambda: self._sao_chep(muc["mat_khau"], "mật khẩu")).pack(side="left", padx=(4, 0))

        ttk.Label(self.chi_tiet, text="Ghi chú:").grid(row=3, column=0, sticky="nw", pady=4)
        ttk.Label(self.chi_tiet, text=muc["ghi_chu"] or "—", wraplength=300, justify="left").grid(
            row=3, column=1, columnspan=2, sticky="w", padx=8)

        hang = ttk.Frame(self.chi_tiet)
        hang.grid(row=4, column=0, columnspan=3, sticky="w", pady=(16, 0))
        ttk.Button(hang, text="Sửa", command=lambda: self._hop_sua(self._ten_dang_chon)).pack(side="left")
        ttk.Button(hang, text="Xóa", command=self._xoa_muc).pack(side="left", padx=6)

    def _bat_tat_hien(self):
        self._hien_mat_khau = not self._hien_mat_khau
        self._hien_chi_tiet()

    # ================= Clipboard =================
    def _sao_chep(self, gia_tri, ten):
        self.root.clipboard_clear()
        self.root.clipboard_append(gia_tri)
        self._noi_dung_clipboard = gia_tri
        if self._hen_clipboard is not None:
            self.root.after_cancel(self._hen_clipboard)
        self._hen_clipboard = self.root.after(XOA_CLIPBOARD_SAU_GIAY * 1000, self._xoa_clipboard)
        self.trang_thai.config(text=f"Đã sao chép {ten}. Clipboard sẽ tự xóa sau {XOA_CLIPBOARD_SAU_GIAY} giây.")

    def _xoa_clipboard(self):
        self._hen_clipboard = None
        try:
            # Chỉ xóa nếu clipboard vẫn là thứ mình đã chép (không xóa nhầm thứ người dùng chép sau đó)
            if self.root.clipboard_get() == self._noi_dung_clipboard:
                self.root.clipboard_clear()
                self.root.clipboard_append("")
        except tk.TclError:
            pass
        self._noi_dung_clipboard = None
        if self.vault is not None:
            self.trang_thai.config(text="Đã xóa clipboard.")

    # ================= Hộp thoại =================
    def _tao_hop(self, tieu_de):
        hop = tk.Toplevel(self.root)
        hop.title(tieu_de)
        hop.transient(self.root)
        hop.resizable(False, False)
        hop.grab_set()
        khung = ttk.Frame(hop, padding=16)
        khung.pack(fill="both", expand=True)
        self._cua_so_con.append(hop)
        hop.bind("<Destroy>", lambda e: self._cua_so_con.remove(hop) if e.widget is hop and hop in self._cua_so_con else None)
        return hop, khung

    def _hop_sua(self, ten_cu):
        if self.vault is None:
            return
        muc = self.vault.lay(ten_cu) if ten_cu else {"tai_khoan": "", "mat_khau": "", "ghi_chu": ""}
        hop, k = self._tao_hop("Sửa mục" if ten_cu else "Thêm mục mới")

        bien_ten = tk.StringVar(value=ten_cu or "")
        bien_tk = tk.StringVar(value=muc["tai_khoan"])
        bien_mk = tk.StringVar(value=muc["mat_khau"])
        bien_gc = tk.StringVar(value=muc["ghi_chu"])
        bien_hien = tk.BooleanVar(value=False)

        ttk.Label(k, text="Tên dịch vụ:").grid(row=0, column=0, sticky="w", pady=4)
        o_ten = ttk.Entry(k, textvariable=bien_ten, width=34)
        o_ten.grid(row=0, column=1, columnspan=2, pady=4)
        o_ten.focus_set()
        ttk.Label(k, text="Tài khoản:").grid(row=1, column=0, sticky="w", pady=4)
        ttk.Entry(k, textvariable=bien_tk, width=34).grid(row=1, column=1, columnspan=2, pady=4)

        ttk.Label(k, text="Mật khẩu:").grid(row=2, column=0, sticky="w", pady=4)
        o_mk = ttk.Entry(k, textvariable=bien_mk, width=22, show="•")
        o_mk.grid(row=2, column=1, sticky="w", pady=4)
        ttk.Button(k, text="Tạo ngẫu nhiên", command=lambda: bien_mk.set(tao_mat_khau_ngau_nhien(16))).grid(
            row=2, column=2, padx=(4, 0))
        ttk.Checkbutton(k, text="Hiện mật khẩu", variable=bien_hien,
                        command=lambda: o_mk.config(show="" if bien_hien.get() else "•")).grid(
            row=3, column=1, sticky="w")

        ttk.Label(k, text="Ghi chú:").grid(row=4, column=0, sticky="w", pady=4)
        ttk.Entry(k, textvariable=bien_gc, width=34).grid(row=4, column=1, columnspan=2, pady=4)

        def luu():
            if self.vault is None:      # vault đã tự khóa trong lúc hộp thoại đang mở
                return
            ten = bien_ten.get().strip()
            if not ten or not bien_mk.get():
                messagebox.showerror("Thiếu thông tin", "Cần nhập tên dịch vụ và mật khẩu.", parent=hop)
                return
            if ten != ten_cu and ten in self.vault.danh_sach():
                if not messagebox.askyesno("Trùng tên", f"“{ten}” đã có. Ghi đè?", parent=hop):
                    return
            try:
                self.vault.them(ten, bien_tk.get(), bien_mk.get(), bien_gc.get())
                if ten_cu and ten != ten_cu:
                    self.vault.xoa(ten_cu)
            except OSError as e:
                messagebox.showerror("Không lưu được", str(e), parent=hop)
                return
            self._ten_dang_chon = ten
            self._hien_mat_khau = False
            hop.destroy()
            self._cap_nhat_danh_sach()
            self._hien_chi_tiet()
            self.trang_thai.config(text=f"Đã lưu “{ten}”.")

        hang = ttk.Frame(k)
        hang.grid(row=5, column=0, columnspan=3, pady=(12, 0))
        ttk.Button(hang, text="Lưu", command=luu).pack(side="left")
        ttk.Button(hang, text="Hủy", command=hop.destroy).pack(side="left", padx=6)

    def _xoa_muc(self):
        ten = self._ten_dang_chon
        if ten and messagebox.askyesno("Xóa", f"Xóa “{ten}”? Không thể hoàn tác."):
            if self.vault is None:      # vault đã tự khóa trong lúc hộp thoại đang mở
                return
            self.vault.xoa(ten)
            self._ten_dang_chon = None
            self._cap_nhat_danh_sach()
            self._hien_chi_tiet()
            self.trang_thai.config(text=f"Đã xóa “{ten}”.")

    def _hop_doi_mat_khau_chinh(self):
        hop, k = self._tao_hop("Đổi mật khẩu chính")
        bien_cu, o_cu = self._o_mat_khau(k)
        bien_moi, o_moi = self._o_mat_khau(k)
        bien_moi2, o_moi2 = self._o_mat_khau(k)
        for i, (nhan, o) in enumerate([("Mật khẩu hiện tại:", o_cu), ("Mật khẩu mới:", o_moi), ("Nhập lại:", o_moi2)]):
            ttk.Label(k, text=nhan).grid(row=i, column=0, sticky="w", pady=4)
            o.grid(row=i, column=1, pady=4)
        o_cu.focus_set()

        def doi():
            if self.vault is None:
                return
            # Xác minh lại mật khẩu hiện tại: người khác ngồi vào máy đang mở cũng không đổi được
            try:
                Vault.mo(self.path, bien_cu.get())
            except SaiMatKhau:
                messagebox.showerror("Lỗi", "Mật khẩu hiện tại không đúng.", parent=hop)
                return
            if bien_moi.get() != bien_moi2.get():
                messagebox.showerror("Lỗi", "Hai mật khẩu mới không khớp.", parent=hop)
                return
            try:
                self.vault.doi_mat_khau_chinh(bien_moi.get())
            except (ValueError, OSError) as e:
                messagebox.showerror("Lỗi", str(e), parent=hop)
                return
            hop.destroy()
            self.trang_thai.config(text="Đã đổi mật khẩu chính.")

        ttk.Button(k, text="Đổi", command=doi).grid(row=3, column=0, columnspan=2, pady=(12, 0))

    # ================= Khóa / thoát =================
    def khoa(self, thong_bao=""):
        for hop in list(self._cua_so_con):
            hop.destroy()
        self._cua_so_con.clear()
        if self._hen_khoa is not None:
            self.root.after_cancel(self._hen_khoa)
            self._hen_khoa = None
        if self._hen_clipboard is not None:
            self.root.after_cancel(self._hen_clipboard)
            self._xoa_clipboard()
        if self.vault is not None:
            self.vault.khoa()
        self.vault = None
        self._ten_dang_chon = None
        self.man_hinh_dang_nhap(thong_bao)

    def _tu_khoa(self):
        self._hen_khoa = None
        self.khoa(f"Đã tự khóa sau {TU_KHOA_SAU_GIAY // 60} phút không thao tác.")

    def thoat(self):
        if self._hen_clipboard is not None:
            self.root.after_cancel(self._hen_clipboard)
            self._xoa_clipboard()
        if self.vault is not None:
            self.vault.khoa()
        self.root.destroy()


def chay(path=FILE_VAULT):
    root = tk.Tk()
    App(root, path)
    root.mainloop()