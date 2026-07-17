UPDATE tbl_san_pham
SET hinh_anh_url = REPLACE(
    REPLACE(
        REPLACE(hinh_anh_url, '.jpg.webp.webp', '.jpg.webp'),
        '.jpg', '.jpg.webp'
    ),
    '.jpg.webp.webp', '.jpg.webp'
)
WHERE hinh_anh_url IS NOT NULL;

UPDATE tbl_san_pham
SET hinh_anh_url = REPLACE(
    REPLACE(
        REPLACE(hinh_anh_url, '.jpeg.webp.webp', '.jpeg.webp'),
        '.jpeg', '.jpeg.webp'
    ),
    '.jpeg.webp.webp', '.jpeg.webp'
)
WHERE hinh_anh_url IS NOT NULL;

UPDATE tbl_san_pham
SET hinh_anh_url = REPLACE(
    REPLACE(
        REPLACE(hinh_anh_url, '.png.webp.webp', '.png.webp'),
        '.png', '.png.webp'
    ),
    '.png.webp.webp', '.png.webp'
)
WHERE hinh_anh_url IS NOT NULL;
