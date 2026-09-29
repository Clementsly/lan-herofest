# Site LAN HeroFest Fortnite 2026

- `/` : page joueurs (connexion Discord → clé si rôle « Confirmed Players », sinon support uniquement ; bouton invité sans Discord pour le support).
- `/admin` : ton panneau (START / STOP LE DISPATCH + messagerie avec tous les joueurs).

## 1. Créer l'application Discord (5 min)
1. Va sur https://discord.com/developers/applications → **New Application** (ex. « HeroFest LAN »).
2. Onglet **OAuth2** : copie le **Client ID**, clique **Reset Secret** et copie le **Client Secret**.
3. Dans **Redirects**, ajoute : `https://TON-SITE.onrender.com/auth/callback` (à corriger avec la vraie adresse après l'étape 2). Enregistre.
> Aucun bot à ajouter : le site lit le rôle du joueur via sa connexion Discord.

## 2. Mettre en ligne sur Render (gratuit)
1. Crée un dépôt GitHub et envoie-y ce dossier (sans `node_modules`).
2. Sur https://render.com → **New** → **Web Service** → choisis le dépôt.
3. Runtime **Node**, Build command `npm install`, Start command `npm start`, plan **Free**.
4. Dans **Environment**, ajoute les variables de `.env.example` :
   - `DISCORD_CLIENT_ID`, `DISCORD_CLIENT_SECRET`
   - `DISCORD_REDIRECT_URI` = `https://<ton-adresse>.onrender.com/auth/callback`
   - `DISCORD_GUILD_ID` = `1554076915663380520` (valeur par défaut)
   - `DISCORD_ROLE_ID` = `1554077319004557372` (valeur par défaut)
   - `ADMIN_PASSWORD` = ton mot de passe admin
   - `SESSION_SECRET` = une longue phrase au hasard
5. Déploie, puis recopie l'adresse exacte dans les Redirects Discord.

## 3. Le jour J
- Ouvre `/admin` 10 min avant pour « réveiller » le serveur (le plan gratuit s'endort après 15 min sans visite).
- Tape la clé → **START LE DISPATCH** : elle apparaît en 2 s chez les Confirmed Players. **STOP LE DISPATCH** : elle disparaît.
- Les messages non lus s'affichent en rouge et dans le titre de l'onglet.

## Tester en local
```
npm install
ADMIN_PASSWORD=test node server.js
```
Puis http://localhost:3000 et http://localhost:3000/admin.

Note : les messages sont stockés dans `data.json` ; sur Render gratuit ils sont effacés à chaque redémarrage (sans importance pour une LAN d'une journée).
