$chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@'
1..2000 | ForEach-Object {
    -join (1..16 | ForEach-Object { $chars[(Get-Random -Maximum $chars.Length)] })
} | Set-Content passwords.txt