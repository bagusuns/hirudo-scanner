# Publikasi GitHub dan pemakaian dari repo lokal

## Pertama kali (upload dari Kali)

1. Di GitHub, buat repository kosong bernama `hirudo-android-ioc-scanner` (**jangan** pilih Initialize with README, license, atau `.gitignore`, karena sudah disertakan).
2. Dari folder proyek di Kali, jalankan:

```bash
cd ~/android_project/hirudo-android-ioc-scanner
git init
git branch -M main
git add .
git status
git commit -m "Initial release: read-only Hirudo Android IOC scanner v1.0"
git remote add origin git@github.com:USERNAME/hirudo-android-ioc-scanner.git
git push -u origin main
```

Ganti `USERNAME` dengan username GitHub Anda. Untuk SSH, daftarkan public SSH key Kali di pengaturan GitHub. Jika memakai HTTPS, gunakan GitHub Personal Access Token, bukan password akun GitHub.

## Komputer lain (mengambil repo pertama kali)

```bash
git clone git@github.com:USERNAME/hirudo-android-ioc-scanner.git
cd hirudo-android-ioc-scanner
python3 scanner.py
```

## Sesudah perubahan diterbitkan ke GitHub

Di mesin yang sudah di-clone:

```bash
cd ~/android_project/hirudo-android-ioc-scanner
git pull --ff-only origin main
python3 scanner.py
```

Perintah `git pull` digunakan untuk **mengambil perubahan yang sudah ada di remote**, bukan mengunggah file. Untuk mengunggah perubahan dari lokal gunakan `git add`, `git commit`, lalu `git push`.

> Pastikan `git status` tidak menampilkan `reports/`, `*.apk`, atau informasi perangkat pribadi sebelum push.
