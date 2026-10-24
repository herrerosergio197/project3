$usuarios = @("admin", "backup", "developer", "ftpuser", "guest", "manager", "root", "soporte", "test", "usuario", "zadmin")

foreach ($u in $usuarios) {
    $path = "C:\SSHData\$u"
    
    # 1. Deshabilitar herencia (para que no hereden permisos globales)
    icacls $path /inheritance:d
    
    # 2. Quitar el acceso a cualquier usuario común
    icacls $path /remove "Usuarios"
    icacls $path /remove "Authenticated Users"
    icacls $path /remove "Todos"
    
    # 3. Dar acceso total solo a ese usuario específico y a los Administradores
    icacls $path /grant "${u}:(OI)(CI)(F)"
    icacls $path /grant "Administradores:(OI)(CI)(F)"
}