# Hirudo Android IOC Scanner

Scanner **read-only terhadap perangkat Android** berbasis Python 3 + ADB untuk melakukan *triage* IOC malware perbankan Android **Hirudo**, sebagaimana dipublikasikan ThreatFabric pada Oktober 2026.

> **Penting:** Hasil `NO_KNOWN_IOC_MATCH` **bukan sertifikat bahwa HP bebas malware**. Proyek ini bukan antivirus dan tidak mendeteksi semua versi Hirudo, seluruh APK bank yang dimodifikasi, atau ancaman Android lainnya.

## Fitur

- Mendeteksi 6 package name IOC Hirudo yang diketahui.
- Membandingkan SHA-256 APK dengan 6 hash IOC resmi.
- Opsi `--hash-all` untuk memeriksa semua aplikasi pihak ketiga yang terdaftar.
- Membaca konfigurasi Accessibility Services (informasi pendukung, bukan indikator pasti infeksi).
- Verifikasi signature APK dan pembacaan fingerprint signer jika tersedia `apksigner` (**belum membandingkan** dengan sertifikat resmi bank).
- Menghasilkan laporan JSON dan CSV lokal pada folder `reports/`.
- Tanpa root, tanpa *install*, *uninstall*, *push*, maupun perubahan setting HP.

## Kebutuhan

- Linux / Kali Linux dan Python 3.9+
- Android SDK Platform Tools (`adb`)
- Opsional: Android SDK Build Tools (`apksigner`)
- Kabel USB data dan **USB debugging** pada HP milik sendiri atau perangkat yang Anda mendapat izin untuk periksa

Kali Linux:

```bash
sudo apt update
sudo apt install -y adb apksigner
```

## Jalankan

```bash
adb devices -l
python3 scanner.py
```

Pastikan status ADB `device`, bukan `unauthorized`.

Untuk mencocokkan hash seluruh aplikasi pihak ketiga:

```bash
python3 scanner.py --hash-all
```

Untuk hanya mendeteksi package dan membaca setting Accessibility, **tanpa menyalin APK**:

```bash
python3 scanner.py --no-pull
```

Jika tersambung beberapa HP:

```bash
python3 scanner.py --serial SERIAL_PERANGKAT
```

Untuk menentukan direktori keluaran:

```bash
python3 scanner.py --hash-all --output reports
```

`--hash-all` dapat berlangsung beberapa menit dan membutuhkan ruang disk sementara untuk APK. Hasil laporan otomatis dibuat dengan waktu UTC.

## Makna hasil

| Status | Interpretasi |
|---|---|
| `HASH_MATCH` | SHA-256 suatu APK identik dengan salah satu sampel Hirudo yang ada di IOC |
| `PACKAGE_MATCH_REVIEW` | Package name IOC ditemukan, tetapi hash belum cocok atau tidak dapat dibaca; perlu investigasi |
| `NOT_INSTALLED` | Package IOC tersebut tidak ditemukan dalam daftar aplikasi pihak ketiga terpasang |
| `NO_KNOWN_IOC_MATCH` | APK yang diperiksa tidak cocok dengan hash IOC yang diketahui |

Perhatikan pula `apk_status`. Jika nilainya `partial` atau `unavailable`, pemeriksaan hash belum lengkap. Jika `signers[].certificate.status` adalah `not_checked`, `apksigner` belum tersedia. Signature yang valid **bukan** bukti bahwa penerbitnya merupakan bank asli; diperlukan referensi sertifikat resmi yang tervalidasi secara independen.

## Model keamanan: READ-ONLY pada perangkat Android

Scanner menggunakan `adb devices`, `adb shell pm list packages -3`, `adb shell pm path`, `adb shell settings get secure enabled_accessibility_services`, dan `adb pull`. `apksigner` dan perhitungan SHA-256 hanya berjalan atas salinan APK lokal. Salinan sementara dihapus saat pemrosesan selesai. Tidak ada permintaan jaringan keluar dari program scanner; `iocs.json` berisi IOC jaringan sebagai **referensi saja**, bukan untuk memindai lalu lintas DNS/C2.

USB debugging perlu diaktifkan dan diotorisasi pada perangkat; ini mengubah keadaan debugging perangkat di luar operasi scanner. Setelah audit, matikan USB debugging bila tidak diperlukan.

## Privasi

Laporan JSON/CSV berisi serial perangkat, daftar aplikasi yang diperiksa, fingerprint dan metadata. **Jangan commit `reports/` ke GitHub.** Folder ini sudah dikecualikan dari Git melalui `.gitignore`. Jangan mengunggah APK hasil `adb pull`, terutama APK aplikasi keuangan.

## Keterbatasan

- Basis IOC hanya mencakup 6 APK dropper/RAT yang dirinci ThreatFabric, bukan 8 APK bank hasil modifikasi.
- Malware bisa mengubah package name dan SHA-256.
- Tidak ada analisis behavioral, network forensics, pemeriksaan root, atau deteksi menyeluruh terhadap kompromi perangkat.
- Package yang terpasang untuk user lain dan aplikasi sistem mungkin tidak termasuk hasil `pm list packages -3`.
- Pengecekan Accessibility dapat bernilai `null` dan **tidak** membuktikan aman ataupun terinfeksi.
- Install source (`com.android.vending`) **tidak** diverifikasi sebagai bukti kriptografis.

## Testing

```bash
python3 -m unittest discover -s tests -v
python3 -m py_compile scanner.py
```

Pengujian unit menggunakan mock dan tidak memerlukan HP. Pengujian lapangan tetap memerlukan Android berizin.

## Sumber IOC dan kredit

ThreatFabric, *Hirudo: From Fake Updates to Patched Banking Apps*: https://www.threatfabric.com/blogs/hirudo-from-fake-updates-to-patched-banking-apps

IOC milik masing-masing penerbit sumber; proyek ini independen dan **tidak berafiliasi dengan ThreatFabric, Google, atau bank mana pun**.

## Lisensi

MIT License — lihat [LICENSE](LICENSE).
