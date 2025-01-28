# Informe Técnico

# Índice

[Parte 1 - SQLi](#parte-1---sqli)
- [SQLi error inicio de sesión](#a-sqli-error-inicio-de-sesión)  
- [Ataque de diccionario para impersonar usuarios](#b-ataque-de-diccionario-para-impersonar-usuarios)  
- [Vulnerabilidad en SQLite3::escapeString() y solución](#c-vulnerabilidad-en-sqlite3escapestring-y-solución)  
- [Publicar comentarios en nombre de otros usuarios mediante vulnerabilidades](#d-publicar-comentarios-en-nombre-de-otros-usuarios-mediante-vulnerabilidades)  

[Parte 2 - XSS](#parte-2---xss)
- [Crear un comentario con un alert de JavaScript](#a-crear-un-comentario-con-un-alert-de-javascript)  
- [Explicación del uso de &amp; en lugar de & en enlaces GET](#b-explicación-del-uso-de--en-lugar-de--en-enlaces-get)  
- [Vulnerabilidad en show_comments.php y corrección](#c-vulnerabilidad-en-show_commentsphp-y-corrección)  
- [Identificar otras páginas afectadas por XSS y análisis](#d-identificar-otras-páginas-afectadas-por-xss-y-análisis)  

[Parte 3 - Control de acceso, autenticación y sesiones de usuarios](#parte-3---control-de-acceso-autenticación-y-sesiones-de-usuarios)
- [Medidas de seguridad para evitar un registro inseguro](#a-medidas-de-seguridad-para-evitar-un-registro-inseguro)  
- [Medidas de seguridad para asegurar el login](#b-medidas-de-seguridad-para-asegurar-el-login)  
- [Restricciones para el acceso a register.php](#c-restricciones-para-el-acceso-a-registerphp)  
- [Configuración de la carpeta private para evitar acceso no autorizado](#d-configuración-de-la-carpeta-private-para-evitar-acceso-no-autorizado)  
- [Análisis y aseguramiento del flujo de sesiones de usuarios](#e-análisis-y-aseguramiento-del-flujo-de-sesiones-de-usuarios)  

[Parte 4 - Servidores web](#parte-4---servidores-web)
- [Medidas de seguridad para reducir riesgos en el servidor web](#a-medidas-de-seguridad-para-evitar-un-registro-inseguro)  

[Parte 5 - CSRF](#parte-5---csrf)
- [Botón Profile con formulario malicioso en list_players.php](#a-botón-profile-con-formulario-malicioso-en-list_playersphp)  
- [Creación de un comentario para un ataque CSRF sin interacción del usuario](#b-creación-de-un-comentario-para-un-ataque-csrf-sin-interacción-del-usuario)  
- [Condiciones necesarias para que el ataque funcione](#c-condiciones-necesarias-para-que-el-ataque-funcione)  
- [Blindaje contra CSRF usando POST y ataque alternativo](#d-blindaje-contra-csrf-usando-post-y-ataque-alternativo)  

<br>
<br>

---

# Parte 1 - SQLi
## a) SQLi error inicio de sesión

| Escribo los valores … | “ |
| :---- | :---- |
| En el campo … | User |
| Del formulario de la página … | list_players.php |
| La consulta SQL que se ejecuta es … | SELECT userId, password FROM users WHERE username \= """ |
| Campos del formulario web utilizados en la consulta SQL … | User |
| Campos del formulario web no utilizados en la consulta SQL … | Password |

<br>

---

## b) Ataque de diccionario para impersonar usuarios

| Explicación del ataque … | El ataque consiste en repetir un payload de SQL Injection para obtener nombres automáticamente utilizando en cada interacción una contraseña diferente del diccionario |
| :---- | :---- |
| Campo de usuario con el que el ataque ha tenido éxito | " OR password="1234" \-- \- |
| Campo de contraseña con el que el ataque ha tenido éxito | 1234 |

<br>

---

## c) Vulnerabilidad en SQLite3::escapeString() y solución

| Explicación del error … | La función utiliza ‘SQLite3::escapeString()’ para intentar sanitizar la entrada del usuario. Sin embargo, este método no es suficiente para prevenir inyecciones SQL porque la consulta sigue construyéndose dinámicamente mediante concatenación de cadenas. Esto permite que un atacante inyecte código SQL válido. |
| :---- | :---- |
| Solución: Cambiar la línea con el código … | $sql \= "SELECT userId FROM users WHERE username \= '" . $username . "' AND password \= '" . $password . "'"; |
| … por la siguiente línea … | php $stmt \= $db-\>prepare('SELECT userId FROM users WHERE username \= ? AND password \= ?'); $stmt-\>bindValue(1, $username, SQLITE3\_TEXT); $stmt-\>bindValue(2, $password, SQLITE3\_TEXT); $result \= $stmt-\>execute(); |

<br>

---

## d) Publicar comentarios en nombre de otros usuarios mediante vulnerabilidades

| Vulnerabilidad detectada … | Falta de validación y escape adecuado de entradas del usuario. Aunque se utiliza `SQLite3::escapeString()` para sanitizar la entrada del comentario, esta medida no es suficiente para prevenir ataques como la inyección de código malicioso. Esto podría ser explotado para realizar ataques como XSS (Cross-Site Scripting). |
| :---- | :---- |
| Descripción del ataque … | **Envío de comentarios maliciosos.** Al aprovechar la falta de validación y escape completo en los datos del formulario, un atacante podría inyectar código HTML o JavaScript en los comentarios. Este código se almacenaría en la base de datos y se ejecutaría en los navegadores de otros usuarios, permitiendo robar cookies, manipular interfaces o realizar acciones no autorizadas. |
| ¿Cómo podemos hacer que sea segura esta entrada? | **Sanitización estricta y validación del contenido.** 1. Usar funciones de sanitización como `htmlspecialchars()` o `htmlentities()` antes de mostrar cualquier dato del comentario almacenado en la base de datos. 2. Implementar una lista blanca para permitir solo contenido específico en los comentarios, como texto plano, prohibiendo etiquetas HTML o scripts. 3. Realizar validaciones adicionales en el lado del servidor y no depender solo de validaciones del cliente. 4. Emplear librerías especializadas para prevenir XSS y otras vulnerabilidades de entrada. |

<br>
<br>

---


# Parte 2 - XSS

## a) Crear un comentario con un alert de JavaScript
| Introduzco el mensaje … | `\<script\>alert('¡Vulnearbilidad XSS\!');\</script\>` |
| :---- | :---- |
| En el formulario de la página … | En el formulario de comentarios de add\_comment.php |

<br>

---


## b) Explicación del uso de & en lugar de & en enlaces GET
| Explicación … | El uso de \&amp; en lugar de & es necesario porque & tiene un significado especial en HTML. Usar \&amp; asegura que el navegador interprete correctamente el símbolo como un ampersand y no lo confunda con el inicio de una entidad HTML. En los enlaces con parámetros GET, esto previene errores de interpretación y asegura que los parámetros sean correctamente procesados. |
| :---- | :---- |

<br>

---


## c) Vulnerabilidad en show_comments.php y corrección
| ¿Cuál es el problema? | El contenido de los comentarios se está insertando directamente en el HTML sin ser escapado, lo que permite a los atacantes inyectar código JavaScript malicioso. |
| :---- | :---- |
| Sustituyo el código de la/las líneas … | donde se imprime el cuerpo del comentario: `echo "\<div\>\<h4\> ". $row\['username'\] ."\</h4\>\<p\>commented: " . $row\['body'\] . "\</p\>\</div\>";` |
| … por el siguiente código … | `echo "\<div\>\<h4\> ". $row\['username'\] ."\</h4\>\<p\>commented: " . htmlspecialchars($row\['body'\], ENT\_QUOTES, 'UTF-8') . "\</p\>\</div\>";` |

<br>

---


## d) Identificar otras páginas afectadas por XSS y análisis
| Otras páginas afectadas … | `buscador.html` y `insert_player.php` |
| :---- | :---- |
| ¿Cómo lo he descubierto? | Al revisar el código de estas páginas y notar que no se validaban ni escapaban correctamente las entradas del usuario. Esto permite la posibilidad de inyección de código malicioso, lo que se confirmó al realizar pruebas de XSS, donde los scripts fueron ejecutados al ser mostrados en la página. |

<br>
<br>

---

# Parte 3 - Control de acceso, autenticación y sesiones de usuarios

## a) Medidas de seguridad para evitar un registro inseguro
 Medidas para evitar que el registro sea inseguro:

1. **SQL Injection:** Actualmente, el código está vulnerable a ataques de inyección SQL, ya que utiliza concatenación de cadenas para insertar datos directamente en la consulta SQL. Esto puede ser aprovechado por un atacante para manipular la consulta y obtener acceso no autorizado a la base de datos. La solución es utilizar consultas preparadas y parámetros vinculados, que aseguran que los datos sean tratados correctamente y no como parte de la consulta SQL.
<br>

   **Solución:** En lugar de concatenar las variables en la consulta SQL, se deben usar consultas preparadas, que permiten pasar los parámetros como valores y no como parte de la consulta, protegiendo así la base de datos.

   ```php
   $stmt \= $db-\>prepare('SELECT userId, password FROM users WHERE username \= :username');

   $stmt-\>bindValue(':username', $user, SQLITE3\_TEXT);

   $result \= $stmt-\>execute();`
   ```

<br>


2. **Contraseñas en texto claro:** El código actual almacena las contraseñas en texto claro, lo que las hace vulnerables en caso de una filtración de la base de datos. Para proteger las contraseñas, se debe utilizar un algoritmo de hash seguro, como `password_hash()` en lugar de almacenar la contraseña directamente.

   <br>

	**Solución:** Utilizar `password_hash()` para crear un hash seguro de la contraseña y `password_verify()` al autenticar al usuario.

	```php
 	if (password_verify($password, $row['password'])) {
	```
<br>

3. **Fuerza bruta:** El sistema actual no tiene protección contra ataques de fuerza bruta o bots que intenten registrar usuarios de manera automática. Se pueden implementar medidas como límites de intentos de registro y el uso de captchas.  
<br>

   **Solución:** Implementar un sistema de limitación de intentos para el registro y añadir un CAPTCHA en el formulario de registro para verificar que el usuario es humano.

	```php
   $hashed\_password \= password\_hash($password, PASSWORD\_BCRYPT);

   $stmt \= $db-\>prepare("INSERT INTO users (username, password) VALUES (:username, :password)");

   $stmt-\>bindValue(':username', $username, SQLITE3\_TEXT);

   $stmt-\>bindValue(':password', $hashed\_password, SQLITE3\_TEXT);

   $stmt-\>execute();
	```

<br>

---

## b) Medidas de seguridad para asegurar el login
Medidas para el **login seguro:** 
- **Uso de contraseñas hash:** Como mencionamos en el apartado anterior, debemos usar el hashing para las contraseñas. En el caso de validación del login, `password_verify()` debe ser utilizada para comparar la contraseña introducida con la almacenada.
<br>

- **Uso de cookies seguras:** Las cookies deben configurarse correctamente para evitar ataques como Cross-Site Scripting (XSS) o Cross-Site Request Forgery (CSRF). Esto incluye la definición de la cookie como segura y HTTPOnly, y posiblemente utilizando un token CSRF para asegurar las solicitudes.

Mejoras para las cookies (en `auth.php`):

```php
if ($login_ok == FALSE) {
    setcookie('user', $_COOKIE['user'], time() + 3600, '/', '', true, true);
    setcookie('password', $_COOKIE['password'], time() + 3600, '/', '', true, true);
    setcookie('userId', $_COOKIE['userId'], time() + 3600, '/', '', true, true);
}
```


<br>

---


## c) Restricciones para el acceso a register.php
Para evitar que usuarios no autorizados accedan a la página de registro, se deben agregar verificaciones de autenticación antes de mostrar la página de registro. Si un usuario no está autenticado, se debe redirigir a la página de login.

Implementación de restricción de acceso en `register.php`:

```php
<?php
	require_once dirname(__FILE__) . '/private/auth.php';

	if (!$login_ok) {
    	header("Location: login.php");
    	exit();
	}
?>
```

<br>

---


## d) Configuración de la carpeta private para evitar acceso no autorizado
Es esencial que la carpeta private esté protegida para evitar que usuarios no autorizados accedan a archivos sensibles como las credenciales o la configuración del servidor.

Medidas recomendadas:
1. **Uso de .htaccess:** Hay que asegurarse de proteger la carpeta private utilizando un archivo .htaccess con las siguientes líneas:
	```
	<Directory /path/to/private>
		Order deny,allow
		Deny from all
	</Directory>
	```

2. **Cambiar permisos de la carpeta:** Estar seguros de que los permisos de la carpeta private sean adecuados para evitar que los usuarios puedan acceder a ella, incluso conociendo la ruta completa.
<br>

---


## e) Análisis y aseguramiento del flujo de sesiones de usuarios
La gestión actual de las sesiones no asegura completamente la protección contra posibles ataques como la fijación de sesión o el secuestro de sesiones. Para mejorar la seguridad de las sesiones del usuario, las siguientes medidas han sido implementadas:

1. **Regeneración del ID de sesión tras el inicio de sesión:**  
Al iniciar sesión con éxito, se utiliza `session_regenerate_id(true)` para generar un nuevo ID de sesión único. Esto asegura que un atacante no pueda reutilizar un ID de sesión anterior, evitando ataques de fijación de sesión.

<br>

2. **Cookies seguras para sesiones:**  
Se configura la cookie de sesión con las siguientes propiedades:  
- `secure`: Asegura que las cookies solo se transmitan a través de conexiones HTTPS.  
- `HttpOnly`: Evita que las cookies sean accesibles mediante JavaScript, protegiendo contra ataques XSS.  
  La cookie se establece utilizando: `setcookie(session_name(), session_id(), time() + 3600, '/', '', true, true)`.  

<br>

3. **Expiración y destrucción de la sesión al cerrar sesión:**  
- Cuando el usuario selecciona `Logout`, la sesión se destruye completamente utilizando `session_unset()` para eliminar las variables de sesión y `session_destroy()` para eliminar la sesión en el servidor.  
- La cookie de sesión también se elimina inmediatamente configurando un tiempo en el pasado `(setcookie(session_name(), '', time() - 3600, '/'))`.  
- Finalmente, el usuario es redirigido a la página de inicio con `header("Location: index.php")`.

<br>

Mejoras para la sesión (en `auth.php`):

```php
session_start();
session_regenerate_id(true);

setcookie(session_name(), session_id(), time() + 3600, '/', '', true, true);

if (isset($_POST['Logout'])) {
    session_unset();
    session_destroy();
    setcookie(session_name(), '', time() - 3600, '/');n
    header("Location: index.php");
}

```

<br>

---

# Parte 4 - Servidores web
## Punto 1: Configuración del Servidor Web
Es esencial deshabilitar módulos o servicios que no sean necesarios, disminuyendo así la superficie de ataque. Además, se debe ocultar información sensible del servidor configurando opciones como ServerTokens a Prod y ServerSignature a Off.

---
## Punto 2: Seguridad de las Conexiones
Es fundamental habilitar HTTPS para garantizar que todas las comunicaciones estén encriptadas mediante certificados SSL/TLS. Además, se debe implementar HTTP Strict Transport Security (HSTS) para obligar a los navegadores a realizar únicamente conexiones seguras.

---
## Punto 3: Control de Acceso
Se debe implementar autenticación de dos factores (2FA), añadiendo una capa adicional de protección para los usuarios. Además, la instalación de un cortafuegos de aplicaciones web (WAF) ayudaría a bloquear automáticamente patrones de tráfico malintencionado.

---
## Punto 4: Cabeceras HTTP de Seguridad
La configuración de cabeceras HTTP protege las aplicaciones web frente a amenazas comunes. La cabecera Content-Security-Policy limita los orígenes de scripts y recursos para prevenir ataques de XSS. Otras cabeceras esenciales incluyen X-Frame-Options para evitar ataques de clickjacking, X-Content-Type-Options para evitar la interpretación incorrecta de tipos MIME, y Referrer-Policy para controlar la información de referencia que se envía a otros sitios.

---
## Punto 5: Protección contra Ataques Comunes
Para mitigar ataques de fuerza bruta, es importante limitar el número de intentos de inicio de sesión. La protección contra inyección SQL se logra utilizando consultas preparadas en lugar de concatenar cadenas SQL. Para prevenir ataques XSS, se deben escapar adecuadamente los datos de entrada y salida.

---
## Punto 6: Registro y Monitorización
Habilitar logs detallados de errores y accesos es crucial para detectar actividades sospechosas. Estos registros deben ser supervisados constantemente mediante herramientas de monitoreo y alertas que permitan una respuesta rápida ante incidentes.

---
## Punto 7: Parcheado y Actualización
El servidor web debe mantenerse actualizado con los últimos parches de seguridad. Esto incluye además del software principal (Apache o Nginx) todas las bibliotecas y dependencias utilizadas por la aplicación web. Mantener todo actualizado reduce el riesgo de vulnerabilidades conocidas.

---
## Punto 8: Configuración de Bases de Datos
El servidor web no debe tener acceso directo con privilegios de administrador a las bases de datos. Las aplicaciones deben operar con cuentas que tengan permisos mínimos para realizar sus tareas.

<br>

---

# Parte 5 - CSRF
## a) Botón Profile con formulario malicioso en list_players.php
| En el campo … | http://web.pagos/donate.php?amount=100\&receiver=attacker |
| :---- | :---- |
| Introduzco … | Un formulario oculto en la lista de jugadores, con un botón `Profile` que al hacer clic redirige a la URL de la donación con los parámetros `amount=100` y `receiver=attacker`. |

Este botón `Profile` genera una solicitud GET que redirige al usuario a la URL de donación, simulando que se realiza una donación a la cuenta del atacante.

<br>

---

## b) Creación de un comentario para un ataque CSRF sin interacción del usuario
El objetivo es hacer que la donación se realice automáticamente sin que el usuario tenga que hacer clic en un botón. En este caso, se puede insertar un comentario que contenga un script que haga una solicitud HTTP automáticamente al servidor de pagos, sin necesidad de interacción del usuario.

Para lograr esto, se puede insertar un comentario sobre un jugador en `show_comments.php` que contiene un código JavaScript malicioso. Este código JavaScript se ejecutará automáticamente cuando cualquier usuario visite la página y vea los comentarios del jugador, causando que se realice una donación a la cuenta del atacante.

```php
<script>
  var xhr = new XMLHttpRequest();
  xhr.open("GET", "http://web.pagos/donate.php?amount=100&receiver=attacker", true);
  xhr.send();
</script>
```

<br>

---

## c) Condiciones necesarias para que el ataque funcione
Para que la donación se efectúe, se deben cumplir las siguientes condiciones:

- **Autenticación del usuario**: La víctima debe estar autenticada en la plataforma de pagos (web.pagos), ya que se verifica que el usuario esté logueado antes de procesar la donación.

- **Solicitud válida:** La plataforma debe aceptar la solicitud de donación, incluso si proviene de un atacante, siempre y cuando no valide la fuente correctamente.

- **Cookies y sesión activa:** Si la plataforma usa cookies o sesiones, estas deben ser enviadas con la solicitud, lo que permite que la transacción sea procesada con la identidad del usuario legítimo.

La donación se realiza si el usuario está autenticado y no hay validaciones contra CSRF en la plataforma.

<br>

---

## d) Blindaje contra CSRF usando POST y ataque alternativo
No, el uso de POST no sería suficiente para prevenir el ataque CSRF. Aunque POST es más seguro que GET, el atacante aún puede enviar una solicitud POST maliciosa creando un formulario oculto que envíe los parámetros a donate.php.

El ataque con POST se realizaría de manera similar, enviando un formulario oculto con los parámetros de la donación al servidor de pagos, lo que aún permitiría al atacante ejecutar el ataque si no se implementan medidas como tokens CSRF.