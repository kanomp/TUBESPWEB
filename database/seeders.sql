-- Insert Admin User
INSERT INTO users (name, email, password, phone, address, role) VALUES
('Admin Pembunuh', 'admin@pembunuhbayaran.com', '$2b$12$RT5xNlP1TWg3rdyt9PpS5ekqxABk1XBGMYueU18Y/1QjmVwb4sB4i', '081234567890', 'Bandung, Indonesia', 'admin');

-- Insert Categories
INSERT INTO categories (name, description) VALUES
('Senjata', 'Koleksi senjata dan perlengkapan tempur'),
('Jasa Polisi', 'Layanan keamanan dan penegakan hukum'),
('Jasa Body Guard', 'Layanan pengawal pribadi profesional'),
('Jasa Bebas Hukum', 'Konsultasi dan bantuan hukum'),
('Jasa Membersihkan TKP', 'Layanan pembersihan lokasi kejadian');

-- Insert Sample Products
INSERT INTO products (name, slug, category_id, description, price, stock, image, is_active) VALUES
('Pistol Glock 17', 'pistol-glock-17', 1, 'Pistol semi-otomatis berkualitas tinggi', 5000000, 10, 'glock17.jpg', TRUE),
('AK-47 Assault Rifle', 'ak-47-assault-rifle', 1, 'Senjata serbu legendaris dengan akurasi tinggi', 15000000, 5, 'ak47.jpg', TRUE),
('Kevlar Body Armor', 'kevlar-body-armor', 1, 'Pelindung tubuh anti peluru', 3000000, 20, 'kevlar.jpg', TRUE),
('Sniper Rifle Barrett M82', 'sniper-rifle-barrett-m82', 1, 'Senjata runduk jarak jauh presisi tinggi', 25000000, 3, 'barrett.jpg', TRUE),
('Combat Knife', 'combat-knife', 1, 'Pisau tempur tajam dan tahan lama', 500000, 50, 'knife.jpg', TRUE),
('Paket Jasa Polisi', 'paket-jasa-polisi', 2, 'Layanan penegakan hukum dan keamanan area', 10000000, 5, 'polisi.jpg', TRUE),
('Jasa Pengamanan Event', 'jasa-pengamanan-event', 2, 'Layanan keamanan untuk acara besar', 5000000, 10, 'security.jpg', TRUE),
('Paket Body Guard Premium', 'paket-body-guard-premium', 3, 'Pengawal pribadi 24/7 dengan pelatihan khusus', 25000000, 3, 'bodyguard.jpg', TRUE),
('Body Guard VIP', 'body-guard-vip', 3, 'Pengawal pribadi untuk tokoh penting', 15000000, 5, 'vip-guard.jpg', TRUE),
('Konsultasi Hukum Lengkap', 'konsultasi-hukum-lengkap', 4, 'Layanan bantuan hukum untuk berbagai kasus', 5000000, 10, 'hukum.jpg', TRUE),
('Jasa Advokat', 'jasa-advokat', 4, 'Layanan pengacara profesional', 8000000, 8, 'advokat.jpg', TRUE),
('Paket Pembersihan TKP Profesional', 'paket-pembersihan-tkp', 5, 'Layanan pembersihan lokasi kejadian perkara', 8000000, 8, 'tkp.jpg', TRUE),
('Jasa Cleanup Crime Scene', 'jasa-cleanup-crime-scene', 5, 'Layanan pembersihan TKP dengan peralatan profesional', 12000000, 5, 'cleanup.jpg', TRUE),
('G2 COMBAT A1', 'g2-combat-a1-pistol', 1, 'Pistol 9 mm cocok untuk penggunaan taktis oleh militer dan Penegakan Hukum', 6500000, 12, 'G2_Combat_A1_Pistol.jpg', TRUE),
('G2 Premium', 'g2-premium-pistol', 1, 'Pistol 9 mm dibuat untuk memenangkan kompetisi menembak', 6800000, 8, 'G2_Premium_Pistol.jpg', TRUE),
('G2 ELITE', 'g2-elite-pistol', 1, 'Pistol 9 mm cocok untuk penggunaan layanan standar oleh militer dan Penegakan Hukum', 6200000, 10, 'G2_Elite_Pistol.jpg', TRUE),
('MAG-4', 'mag-4-pistol', 1, 'Pistol 9 mm dengan laras 4 inci yang dirancang untuk penggunaan Militer dan Penegakan Hukum', 5800000, 15, 'Mag4_Pistol.jpg', TRUE),
('P3A', 'p3a-pistol', 1, 'Pistol 7,65 x 17 mm (.32 ACP) dirancang untuk pertahanan diri', 4500000, 20, 'P3A_Pistol.jpg', TRUE),
('SAR-2 Grenade Launcher', 'sar-2-grenade-launcher', 1, 'Peluncur 38 mm untuk penggunaan Penegakan Hukum, dapat menembakkan gas air mata, asap, dan bola karet', 12000000, 5, 'SAR2_GrenadeLauncher.jpg', TRUE),
('SPG1A V2 Grenade Launcher', 'spg1a-v2-grenade-launcher', 1, 'Peluncur granat 40 mm untuk keperluan Militer, dapat dipasang pada Senapan Serbu SS1', 14000000, 4, 'SPG1A_V2_GrenadeLauncher.jpg', TRUE),
('SPG1A V3 Grenade Launcher', 'spg1a-v3-grenade-launcher', 1, 'Peluncur granat 40 mm untuk keperluan Militer, cocok dipasang pada Senapan Serbu Laras Pendek SS2-V5', 15000000, 4, 'SPG1A_V3_GrenadeLauncher.jpg', TRUE),
('SPG1A V4 Grenade Launcher', 'spg1a-v4-grenade-launcher', 1, 'Peluncur granat 40 mm untuk keperluan Militer, cocok dipasang pada Senapan Serbu SS2-V4', 16000000, 3, 'SPG1A_V4_GrenadeLauncher.jpg', TRUE),
('Mo-1 Mortar', 'mo-1-mortar', 1, 'Peluncur Mortar Komando 60 mm untuk penggunaan Militer, dirancang untuk menyerang posisi musuh jarak pendek', 18000000, 3, 'Mo1_Mortar.jpg', TRUE),
('Mo-2 Mortar', 'mo-2-mortar', 1, 'Peluncur Mortar Jarak Jauh 60 mm untuk penggunaan Militer, dirancang untuk menyerang posisi musuh jarak jauh', 22000000, 2, 'Mo2_Mortar.jpg', TRUE),
('Mo-3 Mortar', 'mo-3-mortar', 1, 'Peluncur Mortir 81 mm untuk penggunaan Militer, dirancang untuk menyerang posisi musuh jarak jauh', 27000000, 2, 'Mo3_Mortar.jpg', TRUE),
('SS2 V1 Assault Rifle', 'ss2-v1-assault-rifle', 1, 'Senapan serbu 5,56 mm untuk penggunaan Militer dan Penegakan Hukum, diuji untuk kondisi medan perang paling menuntut', 20000000, 5, 'SS2_V1_AssaultRifle.jpg', TRUE),
('SS2 V2 Assault Rifle', 'ss2-v2-assault-rifle', 1, 'Karabin 5,56 mm untuk penggunaan Militer dan Penegakan Hukum dengan desain ringkas dan andal', 19000000, 5, 'SS2_V2_AssaultRifle.jpg', TRUE),
('SS2 V3 Assault Rifle', 'ss2-v3-assault-rifle', 1, 'Senapan serbu 5,56 mm cocok untuk penggunaan Militer dan Penegakan Hukum, dengan kemampuan DMR dan stabilitas tinggi', 21000000, 4, 'SS2_V3_AssaultRifle.jpg', TRUE),
('SS2 V4 Assault Rifle', 'ss2-v4-assault-rifle', 1, 'Senapan serbu 5,56 mm untuk penggunaan Militer dan Penegakan Hukum, cocok untuk peran DMR dalam unit tempur', 22000000, 4, 'SS2_V4_AssaultRifle.jpg', TRUE),
('SS2 V5 Assault Rifle', 'ss2-v5-assault-rifle', 1, 'Senapan serbu 5,56 mm untuk penggunaan Militer dan Penegakan Hukum, dengan kondisi uji yang ketat dan performa tinggi', 23000000, 3, 'SS2_V5_AssaultRifle.jpg', TRUE),
('Paket Polisi Damai Premium', 'paket-polisi-damai-premium', 2, 'Layanan jaminan keamanan maksimal dengan jaringan polisi yang telah "diikat" untuk memastikan tidak ada gangguan selama operasi. Termasuk koordinasi dengan aparat setempat dan pengalihan perhatian jika diperlukan.', 50000000, 25, 'Polisi_Damai.jpg', TRUE),
('Body Guard Elite Assassin', 'body-guard-elite-assassin', 3, 'Pengawal pribadi dari mantan tentara bayaran dengan pengalaman tempur di zona perang. Dilengkapi dengan skill menghilangkan ancaman secara permanen dan proteksi 24/7 tanpa jejak.', 75000000, 20, 'Body_Guard.jpg', TRUE),
('Paket Bebas Hukum VIP', 'paket-bebas-hukum-vip', 4, 'Layanan bantuan hukum komprehensif untuk kasus-kasus "khusus" dengan jaringan pengacara korup dan hakim yang bisa "dibujuk". Garansi pembebasan dari segala tuduhan dengan biaya tambahan.', 100000000, 15, 'Bebas_Hukum.jpg', TRUE),
('Paket Cleanup TKP Professional', 'paket-cleanup-tkp-professional', 5, 'Layanan pembersihan lokasi kejadian perkara secara menyeluruh tanpa meninggalkan jejak DNA, sidik jari, atau bukti lainnya. Menggunakan peralatan profesional dan bahan kimia khusus untuk menghilangkan semua evidence.', 30000000, 30, 'Membersihkan_TKP.jpg', TRUE);

-- Insert Sample Customer
INSERT INTO users (name, email, password, phone, address, role) VALUES
('John Doe', 'john@example.com', '$2b$12$RT5xNlP1TWg3rdyt9PpS5ekqxABk1XBGMYueU18Y/1QjmVwb4sB4i', '082123456789', 'Jakarta, Indonesia', 'customer');
