# Cambio de contraseña y sesiones

El cambio de contraseña y el cierre de otras sesiones son operaciones
separadas. Esto permite que la persona decida qué hacer con sus sesiones
existentes después de cambiar su contraseña.

## Cambiar la contraseña

`POST /api/v1/identity/auth/password/change` requiere un access token válido y
recibe `currentPassword` y `newPassword`. El servicio valida la contraseña
actual, aplica las reglas existentes a la nueva y actualiza su hash. La sesión
actual y las demás sesiones permanecen activas. Los enlaces de recuperación de
contraseña pendientes se invalidan.

## Cerrar las demás sesiones (opcional)

Después del cambio, el cliente puede llamar `DELETE
/api/v1/identity/auth/sessions` con el mismo encabezado Bearer. No requiere un
`sessionId`: Identity Service conserva la sesión indicada por `sid` en el JWT
validado por el servidor y revoca las demás sesiones activas del usuario
indicado por `sub`. La operación también marca como revocados los refresh
tokens asociados, en la misma transacción. La respuesta incluye `revokedCount`.

Las renovaciones consultan el estado revocado del refresh token y de su sesión,
por lo que un token revocado no puede crear nuevas credenciales. La sesión
actual y su refresh token no se modifican.

Si el cliente no hace la segunda llamada, las otras sesiones y sus refresh
tokens continúan activos.
