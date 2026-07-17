UPDATE tbl_nguoi_dung
SET password = CASE username
    WHEN 'admin' THEN '$2a$10$yAp9NzxVKS6D3ZAOTLktmuD2NnvLjBLuikcxhZ27SC/2fjWHlBhNO'
    WHEN 'nhanvien01' THEN '$2a$10$VGHODY9NpMaaSEWnOZOk1.36VmGvup9dnsSRhm6oU/ZxgYpo3jAYm'
    WHEN 'khachhang01' THEN '$2a$10$ilnpFJ2MNFbfpO9uTQ2s8Ov7vS4awsSPuGGCTESehoa.JfmJ4mhRG'
    WHEN 'khachhang02' THEN '$2a$10$BnKIwauKjcxTmiUapRZ5leHZ5z8gtknLQ03mBWMJz0PL03mr1oeWm'
    WHEN 'nguyen' THEN '$2a$10$d8HClJqVJaBd/IUApr2X/ev4UmjIVk6lvYA6rCIK2QgmyyPb621fS'
    WHEN 'quan' THEN '$2a$10$BT3ZVQrq0siyGj9xbJ1i4.v6qo/rGzDZll99cStwMvhbnibq33ihO'
    WHEN 'rule1776692940' THEN '$2a$10$2G.WDtji5jIfyp5QQoSi5u2IchAObjNYRuhdw73g26Kh7Iqtu.J0K'
    WHEN 'user1776690398' THEN '$2a$10$HMJByjFwq6U6baLqipDFX.Em8lX9jeJp4.S5uuckup94kmjNr0RN2'
    ELSE password
END
WHERE username IN (
    'admin',
    'nhanvien01',
    'khachhang01',
    'khachhang02',
    'nguyen',
    'quan',
    'rule1776692940',
    'user1776690398'
);
