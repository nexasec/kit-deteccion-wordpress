# Workflows de n8n

Exportados de la instancia de NexaSec y saneados con `herramientas/sanear_n8n.py`. Se importan **inactivos**: hay que
crear las credenciales y reemplazar los marcadores antes de activarlos.

| Workflow | Disparador | Qué hace |
|---|---|---|
| `canary-a-alerta-enriquecida.json` | webhook `nx-canary` | Recibe los golpes a los señuelos, enriquece la IP con AbuseIPDB y GreyNoise y avisa. Marca como crítico el señuelo crítico, el acceso directo al origen y la cabecera de Cloudflare falsificada. |
| `watchdog-del-web-root.json` | webhook `nx-watchdog` | Recibe el inventario con hash del web root y avisa archivos nuevos, modificados o eliminados. |
| `vigia-del-sitio-origen-y-plugins.json` | webhook `nx-vigia` + cada hora | Avisa cuando el origen deja de estar cerrado (y cuando vuelve), las vulnerabilidades nuevas en core, plugins y temas, el vencimiento del dominio, y si alguno de los dos chequeos deja de reportar. |
| `escalar-bloqueos-a-cloudflare.json` | webhook `nx-escalar` | Recibe candidatos del escalador, los enriquece (AbuseIPDB, GreyNoise, Shodan InternetDB) y **pide aprobación en Telegram**. Si se aprueba, crea una IP Access Rule con la nota `nx-escalado` y su fecha de vencimiento. |
| `expirar-bloqueos-de-cloudflare.json` | cada día 04:30 | Retira las IP Access Rules `nx-escalado` vencidas. |
| `errores-de-workflows-a-telegram.json` | error de otro workflow | Avisa por Telegram cuando falla cualquier workflow que lo tenga como *Error Workflow*. |

Los mensajes usan la zona horaria `America/Santiago`; se cambia en los nodos de código.

## Credenciales

| Credencial | Tipo en n8n | Uso | Permiso mínimo |
|---|---|---|---|
| Header Auth | Header Auth | Los cuatro webhooks | Un nombre de cabecera y un secreto largo, los mismos que van en `headers` del `config.json` |
| Telegram | Telegram API | Todas las alertas | Bot propio, solo en el chat de alertas |
| Cloudflare | Header Auth (`Authorization: Bearer …`) | Escalar y expirar | Token con *Zone → Firewall Services → Edit* solo para la zona del sitio |
| AbuseIPDB | Header Auth (`Key`) | Enriquecimiento | Clave gratuita |
| GreyNoise | Header Auth (`key`) | Enriquecimiento | Clave Community |

Si n8n está detrás de Cloudflare Access, los webhooks necesitan una política *Service Auth* y el service token va
también en `headers`.

## Marcadores a reemplazar

| Marcador | Dónde | Qué poner |
|---|---|---|
| `<TELEGRAM_CHAT_ID>` | Nodos de Telegram | El ID del chat de alertas |
| `<CF_ZONE_ID>` | Escalar y expirar | El Zone ID del sitio (Overview del dominio en Cloudflare) |
| `<ID_CREDENCIAL>` | Todos | Se resuelve solo al elegir la credencial en cada nodo |
| `<ID_WORKFLOW_ERRORES>` | *Settings* de cada workflow | El workflow de errores importado |

## Probar sin esperar un ataque

Cada script del servidor trae un modo de prueba que envía un evento sintético con IPs de documentación (RFC 5737):

```bash
python3 escalador.py --prueba
python3 vigia.py --origen --prueba
python3 vigia.py --plugins --prueba
```
