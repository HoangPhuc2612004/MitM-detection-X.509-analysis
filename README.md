# Nghiên cứu và Phát hiện Tấn công Man-in-the-Middle (MITM) qua Phân tích Chứng chỉ số SSL/TLS (NIDS)
## Giới thiệu dự án

Tấn công Man-in-the-Middle (MITM) thông qua việc giả mạo chứng chỉ số SSL/TLS (SSL Stripping, Fake CA, Interception) là một trong những mối đe dọa nghiêm trọng đến tính toàn vẹn và bảo mật dữ liệu người dùng.

Dự án này nghiên cứu và phát triển một hệ thống **Phát hiện Xâm nhập dựa trên Mạng (NIDS)** có khả năng giám sát lưu lượng mạng theo thời gian thực, trích xuất cấu trúc chứng chỉ số X.509 (Issuer, Fingerprint, Extensions, Chain of Trust) và ứng dụng các thuật toán **Machine Learning** để phân tích sâu, phát hiện cũng như cảnh báo các chứng chỉ bất thường/giả mạo.

## Kiến trúc & Luồng xử lý hệ thống

Hệ thống được chia làm 3 mô-đun chính:

1. **Module Thu thập & Tiền xử lý dữ liệu (data_collection/):**
   - Lắng nghe lưu lượng mạng và trích xuất thông tin chứng chỉ SSL/TLS thời gian thực.
   - Thu thập mẫu chứng chỉ "sạch" và chứng chỉ "giả mạo" (được sinh ra từ các công cụ tấn công như `mitmproxy`) để tạo bộ dữ liệu.
   - Tiền xử lý, trích xuất đặc trưng và gộp dữ liệu thành bộ Dataset hoàn chỉnh.

2. **Module Huấn luyện Mô hình (models/):**
   - Huấn luyện mô hình Machine Learning phân loại chứng chỉ hợp lệ và chứng chỉ độc hại.
   - Đánh giá hiệu năng (Detection Rate, False Positive Rate) và xuất mô hình đã tối ưu ('.pkl`/`.joblib').

3. **Module Phát hiện & Cảnh báo thời gian thực (detection/):**
   - Tích hợp mô hình đã huấn luyện vào Core Engine NIDS.
   - Bắt gói tin trực tiếp qua giao diện mạng (sử dụng pyshark/tshark), đối chiếu Whitelist/Fingerprint và đưa ra cảnh báo kịp thời.

## Cấu trúc thư mục
```text
mitm-cert-detection-nids/
├── .gitignore               # Cấu hình bỏ qua các file tạm, báo cáo, dataset lớn
├── README.md                # Tài liệu giới thiệu dự án
├── requirements.txt         # Các thư viện phụ thuộc
├── data/
│   ├── raw/                 # Dữ liệu chứng chỉ thô (sạch & giả)
│   ├── processed/           # Dữ liệu tổng hợp đã qua tiền xử lý
│   └── domains/             # Danh sách domain / Whitelist kiểm thử
└── src/
    ├── data_collection/
    │   ├── lay_cert.py      # Trích xuất thông tin chứng chỉ SSL/TLS
    │   └── gop_dataset.py   # Xử lý và hợp nhất dataset
    ├── models/
    │   └── train_model.py   # Huấn luyện mô hình Machine Learning
    └── detection/
        └── NIDS.py          # Engine phát hiện và cảnh báo tấn công thời gian thực

## Hướng dẫn sử dụng
### 1. Cài đặt thư viện

Mở Terminal tại thư mục dự án và chạy:
pip install -r requirements.txt
Ngoài ra, cần cài đặt **Wireshark/TShark** để NIDS có thể bắt và phân tích gói tin.

### 2. Thu thập và xử lý dữ liệu
cd src/data_collection
py lay_cert.py
py gop_dataset.py

Dữ liệu sau khi xử lý sẽ được lưu trong thư mục 'data/processed/'.

### 3. Huấn luyện mô hình

cd ../models
py train_model.py

Mô hình sau khi huấn luyện sẽ được lưu dưới định dạng '.pkl' để sử dụng cho quá trình phát hiện.

### 4. Chạy NIDS
cd ../detection
py NIDS.py

Nên mở Terminal bằng quyền **Run as administrator** để chương trình có quyền bắt gói tin trên giao diện mạng.
Nhấn Ctrl + C để dừng chương trình.

## Môi trường kiểm thử

Hệ thống được đánh giá trong mạng lab cô lập gồm:

- **Kali Linux:** Mô phỏng máy thực hiện MITM.
- **Windows:** Máy người dùng tạo lưu lượng HTTPS.
- **Ubuntu:** Chạy NIDS để giám sát và phát hiện bất thường.

Môi trường trên chỉ phục vụ kiểm thử. Người dùng không cần cài đặt cả ba máy ảo để chạy chương trình.