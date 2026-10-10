PORT DE KINSHASA — GESTION DES CARTES D’ACCÈS
================================================

CONTENU
- index.html : création, validation, liste et impression des cartes.
- admin.html : gestion des comptes agents (consultation selon permissions).
- verify.html : page publique de vérification par QR code.
- app.js / admin.js : interface.
- netlify/functions/api.mjs : API serveur et contrôles d’autorisation.
- assets/logo-onatra.png : logo ONATRA fourni.
- assets/carte-journalier.jpg : modèle JOURNALIER.
- assets/carte-agent.png : modèle AGENT.
- assets/carte-visiteur.png : modèle VISITEUR.

RÈGLES DES CARTES
1. JOURNALIER : la date de validité est renseignée à l’enregistrement.
2. AGENT : la date de validité est renseignée à l’enregistrement.
3. VISITEUR : validité de 24 heures à partir de la validation par l’administrateur.
4. Une carte est créée en attente. Seul l’administrateur peut la valider.
5. L’impression est disponible uniquement après validation et si la carte n’est pas révoquée.
6. Le QR code mène à la page de vérification de la carte.
7. Les données sont stockées dans Netlify Blobs côté serveur; l’API vérifie les droits.

DÉPLOIEMENT NETLIFY
1. Décompresser l’archive.
2. Dans le dépôt Git connecté au site Netlify, remplacer les fichiers par ceux de cette archive, en conservant toute configuration propre au projet qui ne doit pas être écrasée.
3. Dans Netlify > Site configuration > Environment variables, définir SESSION_SECRET avec une valeur aléatoire longue (au moins 32 caractères/octets). Ne jamais la publier.
4. Déployer et attendre l’état Published.
5. Tester https://VOTRE-SITE/.netlify/functions/api/health ; la réponse attendue contient "ok": true.
6. Vérifier la connexion administrateur, le changement de mot de passe, la création d’une carte, la validation, l’impression et le QR code avant usage opérationnel.

INITIALISATION ADMINISTRATEUR
La version source crée le premier compte administrateur à la première connexion avec les identifiants de démarrage documentés dans AUTHENTIFICATION-NETLIFY.txt. Changez immédiatement le mot de passe par un mot de passe long et unique. Ne communiquez jamais les identifiants au public. Si le compte administrateur existe déjà dans Netlify Blobs, les identifiants de démarrage ne le remplacent pas.

IMPORTANT
- Cette archive est préparée, mais son déploiement et les tests sur le site réel restent à effectuer.
- Le QR code et l’état d’une carte doivent être vérifiés en ligne avant d’autoriser l’accès.
- La sécurité réelle dépend aussi de la configuration Netlify, de la protection du compte administrateur et des tests d’exploitation.

AUTHENTIFICATION
Voir AUTHENTIFICATION-NETLIFY.txt pour les identifiants initiaux et la configuration SESSION_SECRET.
