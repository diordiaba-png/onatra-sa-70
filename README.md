# PORT DE KINSHASA — Gestion des cartes d’accès

Version préparée pour un dépôt GitHub connecté à Netlify.

## Fonctionnalités
- Cartes JOURNALIER, AGENT et VISITEUR.
- Une carte créée reste en attente jusqu’à validation par l’administrateur.
- La carte VISITEUR expire 24 heures après validation.
- Impression après validation avec QR code unique par carte.
- Contrôle QR depuis un téléphone Android/iPhone via `/controle.html` (caméra) ou en ouvrant le QR imprimé.
- Vérification serveur obligatoire : les cartes en attente, expirées, révoquées ou inconnues sont refusées.
- Journal de traçabilité des contrôles, réservé à l’administrateur dans `/admin.html`.
- L’administrateur attribue individuellement le droit « Contrôler les cartes par QR code » aux agents.
- Stockage côté serveur avec Netlify Blobs.
- Assistant de configuration initiale : `/setup-admin.html` (création unique de l’administrateur).
- Remplacement contrôlé de l’ancien administrateur via un jeton temporaire Netlify. Les cartes et comptes agents sont conservés.

## Déploiement via GitHub + Netlify

1. Sauvegardez le dépôt GitHub connecté au site Netlify.
2. Téléversez le contenu de cette archive à la racine du dépôt existant, y compris les fichiers cachés.
3. Dans Netlify → Site configuration → Environment variables, définissez `SESSION_SECRET` avec une valeur aléatoire secrète d’au moins 32 caractères pour les fonctions en contexte Production.
4. Si vous souhaitez remplacer l’ancien administrateur, définissez temporairement `ADMIN_RESET_TOKEN` avec une valeur secrète d’au moins 32 caractères. Ne mettez jamais ce jeton dans GitHub.
5. Enregistrez et redéployez; attendez le statut `Published`.
6. Ouvrez `/setup-admin.html`. Si un administrateur existe, saisissez le jeton temporaire pour supprimer uniquement son enregistrement. Les cartes d’accès et les comptes agents restent conservés.
7. Créez immédiatement le nouvel identifiant et un mot de passe d’au moins 12 caractères. Le serveur refuse la création si un administrateur existe déjà.
8. Supprimez `ADMIN_RESET_TOKEN` de Netlify puis redéployez.
9. Connectez-vous depuis `/admin.html` avec le compte créé.
10. Dans la gestion des agents, cochez « Contrôler les cartes par QR code » pour chaque agent de contrôle autorisé.
11. Ouvrez `/controle.html` sur le téléphone et connectez-vous avec un compte autorisé. L’utilisation de la caméra exige HTTPS et une autorisation du navigateur.


## Important

- La suppression contrôlée ne retire que la clé `admin` du Netlify Blobs store `port-kinshasa-secure`; elle ne supprime pas les cartes ni les comptes agents. La page de configuration peut créer un administrateur seulement si cette clé est absente.
- Si l’API répond qu’aucun administrateur existant n’a été trouvé, arrêtez la procédure : ne supprimez pas le store et ne créez pas de compte de remplacement avant d’avoir vérifié que le site utilise le bon site Netlify et le bon store.
- Si le site Netlify existant est déjà relié à un dépôt, remplacez les fichiers dans ce dépôt plutôt que de créer un nouveau site Netlify. Cela évite de basculer par erreur vers une autre base de données.
- Ne publiez jamais `SESSION_SECRET`, `ADMIN_RESET_TOKEN`, des mots de passe, ni des fichiers `.env`.
- La procédure ne peut pas être considérée comme terminée tant que le déploiement et la connexion ne sont pas testés sur le site réel.
