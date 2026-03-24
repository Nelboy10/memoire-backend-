# 🚀 Memoire Backend — Guide d'Installation de A à Z

Bienvenue sur le backend de la plateforme de gestion de mémoires. Ce guide vous expliquera étape par étape comment configurer le projet en local, de l'installation des prérequis au lancement du serveur.

---

## 📋 1. Prérequis

Assurez-vous d'avoir les outils suivants installés sur votre machine :
- **Python 3.10 ou ou supérieur** : [Télécharger Python](https://www.python.org/downloads/)
- **Git** : [Télécharger Git](https://git-scm.com/downloads)

*(Optionnel)* Un outil comme Postman ou Insomnia pour tester les requêtes API si vous ne passez pas par l'interface web (Django REST Framework fournit cependant une interface navigateur utilisable).

---

## 🛠️ 2. Récupération du projet (Clone)

1. Ouvrez votre terminal (Invite de commandes, PowerShell, ou Terminal sous macOS/Linux)
2. Naviguez vers le dossier de votre choix : `cd chemin/vers/votre/dossier`
3. Clonez le dépôt et entrez dans le dossier :
   ```bash
   git clone <URL_DU_DEPOT_ICI>
   cd memoire-backend-
   ```

---

## 🐍 3. Création de l'Environnement Virtuel

L'environnement virtuel (`venv`) permet d'isoler les dépendances de ce projet du reste de votre système (fortement recommandé).

1. Créez l'environnement virtuel :
   ```bash
   python -m venv venv
   ```
2. **Activez** l'environnement virtuel :
   - Sur **Windows (PowerShell)** : `.\venv\Scripts\Activate.ps1`
   - Sur **Windows (Invite de commandes)** : `.\venv\Scripts\activate.bat`
   - Sur **macOS / Linux** : `source venv/bin/activate`

*(Note : un indicateur `(venv)` devrait apparaître au début de la ligne de votre terminal).*

---

## 📦 4. Installation des Dépendances

Maintenant que l'environnement virtuel est actif, installez toutes les librairies requises par le projet :

```bash
pip install -r requirements.txt
```

---

## ⚙️ 5. Configuration (Variables d'Environnement)

Le projet utilise des variables d'environnement pour sécuriser les clés et configurer la base de données ou les emails.

1. Un fichier `.env.example` est présent à la racine.
2. Copiez son contenu ou renommez-le simplement en **`.env`** :
   - Sur Windows : `copy .env.example .env`
   - Sur Mac/Linux : `cp .env.example .env`
3. **Par défaut, tout fonctionnera sans modifier le `.env`.** Le projet basculera automatiquement sur une base de données locale **SQLite** (`db.sqlite3`) et le mode `DEBUG` est activé.
*(Si vous voulez utiliser une base PostgreSQL externe ou tester l'envoi d'emails réels en SMTP, remplissez les champs du `.env`).*

---

## 🗄️ 6. Initialisation de la Base de Données

Avant de pouvoir utiliser le projet, vous devez construire la structure de la base de données. 

Appliquez les migrations :
```bash
python manage.py migrate
```

*(Cette commande va créer automatiquement le fichier `db.sqlite3` contenant les tables de l'application : Utilisateurs, Entités, Mémoires, Téléchargements).*

---

## 👑 7. Création de l'Administrateur (Superuser)

Pour pouvoir configurer le site, créer des entités, ou juste avoir un accès total à l'API, créez un compte super-administrateur :

```bash
python manage.py createsuperuser
```

Suivez les invites (Vous pouvez laisser l'email vide, mettez juste un nom d'utilisateur et un mot de passe).

---

## ▶️ 8. Lancement du Serveur

Tout est prêt ! Vous pouvez maintenant lancer le serveur local :

```bash
python manage.py runserver
```

Votre serveur est actif sur : **[http://127.0.0.1:8000/](http://127.0.0.1:8000/)**

### Accès au Projet :
- **L'Administration Django** : [http://127.0.0.1:8000/admin/](http://127.0.0.1:8000/admin/) (Utilisez vos identifiants superuser créés à l'étape 7).
- **Racine de l'API REST** : [http://127.0.0.1:8000/api/](http://127.0.0.1:8000/api/)
- **Documentation API Complète** : Référez-vous au fichier `API_DOCUMENTATION.md` fourni à la racine du projet pour connaître toutes les routes disponibles (Authentification JWT, Mémoires, Entités...).
