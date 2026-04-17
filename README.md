# OpenID Federation Demo Server

Een Spring Boot applicatie die een OpenID Federation infrastructuur simuleert met drie entiteiten (anchor, intermediate, leaf). Externe validatielagen kunnen via HTTP een echte trust chain oplossen.

## Lokaal draaien

```bash
mvn spring-boot:run
```

Of via Docker:

```bash
docker build -t federation-demo .
docker run -p 8080:8080 -e BASE_URL=http://localhost:8080 federation-demo
```

## Railway deployen

1. Fork / push deze repo naar GitHub
2. Maak een nieuw Railway project → **Deploy from GitHub repo**
3. Voeg een environment variable toe: `BASE_URL=https://<jouw-railway-url>`
4. Redeploy (Railway pikt de variabele automatisch op)

## Demo via Swagger UI

Open `{BASE_URL}/swagger-ui.html`

Gebruik **POST /verify** met body:

```json
{
  "issuerIdentifier": "{BASE_URL}/leaf",
  "trustAnchorEntityId": "{BASE_URL}/anchor"
}
```

Verwacht resultaat:

```json
{
  "trusted": true,
  "issuer": "{BASE_URL}/leaf",
  "error": null
}
```

## Endpoints

| Method | Path | Content-Type | Beschrijving |
|--------|------|-------------|--------------|
| GET | `/{entity}/.well-known/openid-federation` | `application/entity-statement+jwt` | Entity configuration JWT |
| GET | `/{entity}/fetch?sub=...` | `application/entity-statement+jwt` | Subordinate statement JWT |
| GET | `/info` | `application/json` | Debug-overzicht van alle entiteiten |
| POST | `/verify` | `application/json` | Trust chain validatie |
| GET | `/swagger-ui.html` | `text/html` | Swagger UI |
| GET | `/actuator/health` | `application/json` | Health check (Railway) |
