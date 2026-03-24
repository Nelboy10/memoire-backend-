# 📚 Documentation API — Memoire Backend

**Base URL** : `http://127.0.0.1:8000/api/`

**Authentification** : JWT (Bearer Token)

**Rate Limiting** : 30 req/min (anonyme) · 120 req/min (authentifié)

---

## Table des matières

1. [Authentification](#1-authentification)
2. [Utilisateurs](#2-utilisateurs)
3. [Entités](#3-entités)
4. [Mémoires](#4-mémoires)
5. [Téléchargements](#5-téléchargements)
6. [Dashboard & Statistiques](#6-dashboard--statistiques)
7. [Secrétaire](#7-secrétaire)
8. [Étudiant](#8-étudiant)
9. [Administration](#9-administration)

---

## 1. Authentification

### POST `/api/auth/login/`
Connexion avec JWT.

**Body** :
```json
{
  "username": "string",
  "password": "string"
}
```

**Réponse 200** :
```json
{
  "user": { "id": 1, "username": "...", "email": "...", "role": "..." },
  "access": "eyJ...",
  "refresh": "eyJ...",
  "message": "Connexion réussie"
}
```

**Erreurs** : `400` (champs manquants) · `401` (identifiants incorrects) · `403` (compte désactivé/expiré)

---

### POST `/api/auth/logout/`
🔒 **Authentifié**

**Body** :
```json
{ "refresh": "eyJ..." }
```

**Réponse 200** : `{ "message": "Déconnexion réussie" }`

---

### POST `/api/auth/register-student/`
Inscription d'un étudiant (compte temporaire de 4 jours).

**Body** :
```json
{
  "username": "string",
  "password": "string",
  "email": "email",
  "first_name": "string",
  "last_name": "string",
  "entite": 1
}
```

**Réponse 201** : Retourne `user`, `access`, `refresh`.

---

### GET `/api/auth/current-user/`
🔒 **Authentifié** — Infos de l'utilisateur connecté.

**Réponse 200** :
```json
{
  "id": 1,
  "email": "user@example.com",
  "first_name": "John",
  "last_name": "Doe",
  "is_staff": false,
  "role": "etudiant",
  "entite": 1,
  "entite_nom": "Université X"
}
```

---

### POST `/api/auth/password/change/`
🔒 **Authentifié** — Changer le mot de passe.

**Body** :
```json
{
  "old_password": "string",
  "new_password1": "string",
  "new_password2": "string"
}
```

---

### POST `/api/auth/token/`
Obtenir un token JWT (endpoint standard SimpleJWT).

### POST `/api/auth/token/refresh/`
Rafraîchir le token JWT.

### POST `/api/auth/token/verify/`
Vérifier la validité d'un token.

### POST `/api/auth/token/custom-refresh/`
Endpoint personnalisé de rafraîchissement.

---

## 2. Utilisateurs

### GET `/api/users/`
🔒 **Admin Général** ou **Admin Entité**

Liste des utilisateurs. L'admin d'entité ne voit que les utilisateurs de son entité.

**Réponse 200** :
```json
{
  "count": 10,
  "results": [
    {
      "id": 1,
      "username": "john",
      "email": "john@example.com",
      "first_name": "John",
      "last_name": "Doe",
      "role": "etudiant",
      "entite": 1,
      "date_expiration": "2026-03-28T13:00:00Z",
      "telephone": "",
      "is_expired": false,
      "is_active": true
    }
  ]
}
```

---

### POST `/api/users/`
🔒 **Admin Général** uniquement — Créer un utilisateur.

---

### GET `/api/users/{id}/`
🔒 **Admin Général** ou **Admin Entité** — Détail d'un utilisateur.

---

### PUT/PATCH `/api/users/{id}/`
🔒 **Admin Général** ou **Admin Entité** — Modifier un utilisateur.

---

### DELETE `/api/users/{id}/`
🔒 **Admin Général** ou **Admin Entité** — Supprimer un utilisateur.

---

### GET `/api/users/me/`
🔒 **Authentifié** — Profil de l'utilisateur connecté.

---

### PATCH `/api/users/{id}/update_profile/`
🔒 **Propriétaire uniquement** — Modifier son propre profil.

---

### GET `/api/users/expired_students/`
🔒 **Admin** — Liste des étudiants dont le compte a expiré.

---

## 3. Entités

### GET `/api/entites/`
🔒 **Admin Général** — Liste des entités.

**Réponse 200** :
```json
{
  "results": [
    {
      "id": 1,
      "nom": "Université X",
      "description": "Description...",
      "administrateur": 2,
      "administrateur_name": "Jane Doe"
    }
  ]
}
```

---

### POST `/api/entites/`
🔒 **Admin Général** — Créer une entité.

**Body** :
```json
{
  "nom": "string",
  "description": "string",
  "administrateur": 2
}
```

---

### GET/PUT/PATCH/DELETE `/api/entites/{id}/`
🔒 **Admin Général** — CRUD entité.

---

## 4. Mémoires

### GET `/api/memoires/`
🌐 **Public** — Liste des mémoires publics. Les utilisateurs authentifiés voient plus selon leur rôle.

**Query params** : pagination standard (`?page=1`)

**Réponse 200** :
```json
{
  "count": 50,
  "next": "http://127.0.0.1:8000/api/memoires/?page=2",
  "results": [
    {
      "id": 1,
      "titre": "Titre du mémoire",
      "resume": "Résumé...",
      "fichier": "/media/memoires/file.pdf",
      "auteur": 3,
      "auteur_name": "John Doe",
      "entite": 1,
      "entite_name": "Université X",
      "est_public": true,
      "nb_telechargements": 42,
      "date_soumission": "2026-03-20T10:00:00Z",
      "annee_soumission": 2026,
      "filiere": "Informatique",
      "mots_cles": "IA, Machine Learning"
    }
  ]
}
```

**Fichiers acceptés** : PDF, DOC, DOCX (max 20 Mo)

---

### POST `/api/memoires/`
🔒 **Étudiant** (compte non expiré) — Créer un mémoire. L'auteur et l'entité sont assignés automatiquement.

**Body** (multipart/form-data) :
```
titre: string
resume: string
fichier: File (PDF/DOC/DOCX, max 20 Mo)
annee_soumission: integer
filiere: string
mots_cles: string (optionnel)
```

---

### GET `/api/memoires/{id}/`
🌐 **Public** — Détail d'un mémoire.

---

### PUT/PATCH `/api/memoires/{id}/`
🔒 **Admin / Secrétaire / Auteur** — Modifier un mémoire.

---

### DELETE `/api/memoires/{id}/`
🔒 **Admin / Secrétaire / Auteur** — Supprimer un mémoire.

---

### GET `/api/memoires/search/`
🌐 **Public** — Recherche de mémoires.

**Query params** :
| Param | Description |
|---|---|
| `q` | Recherche texte (titre, résumé, mots-clés, auteur) |
| `filiere` | Filtrer par filière |
| `annee` | Filtrer par année de soumission |
| `entite` | Filtrer par ID d'entité |

**Exemple** : `GET /api/memoires/search/?q=machine+learning&filiere=informatique&annee=2026`

---

### GET `/api/memoires/public/`
🌐 **Public** — Liste des mémoires publics, triés par popularité.

---

### GET `/api/memoires/mes_memoires/`
🔒 **Étudiant** — Ses propres mémoires.

---

### POST `/api/memoires/{id}/download/`
🌐 **Public** — Télécharger un mémoire par email.

**Body** :
```json
{ "email": "user@example.com" }
```

**Réponse 200** : Le fichier est envoyé par email en pièce jointe.

---

### GET `/api/public/memoires/{id}/telecharger/`
🌐 **Public** — Téléchargement direct du fichier PDF.

**Query param optionnel** : `?email=user@example.com` (pour logger le téléchargement)

---

## 5. Téléchargements

### GET `/api/downloads/`
🔒 **Admin / Secrétaire** — Historique des téléchargements.

**Réponse 200** :
```json
{
  "results": [
    {
      "id": 1,
      "email": "user@example.com",
      "memoire": 1,
      "memoire_titre": "Titre...",
      "entite": 1,
      "entite_nom": "Université X",
      "date_telechargement": "2026-03-24T10:00:00Z"
    }
  ]
}
```

---

## 6. Dashboard & Statistiques

### GET `/api/dashboard/stats/`
🔒 **Admin Général** ou **Admin Entité**

**Réponse Admin Général** :
```json
{
  "total_users": 50,
  "total_memoires": 120,
  "total_telechargements": 500,
  "memoires_publics": 100,
  "total_etudiants": 30,
  "etudiants_expires": 5,
  "memoires_par_mois": [{ "mois": "2026-01-01", "count": 10 }],
  "telechargements_par_mois": [{ "mois": "2026-01-01", "count": 50 }]
}
```

---

### GET `/api/statistiques/`
🔒 **Admin** — Liste des statistiques par entité.

### GET `/api/statistiques/global_stats/`
🔒 **Admin** — Statistiques globales.

---

## 7. Secrétaire

### GET `/api/secretaire/dashboard/`
🔒 **Secrétaire** — Dashboard de la secrétaire.

**Réponse 200** :
```json
{
  "entite": "Université X",
  "memoires_en_attente": 3,
  "memoires_ce_mois": 5,
  "telechargements_ce_mois": 20,
  "etudiants_actifs": 10,
  "etudiants_expires_recent": 2,
  "total_memoires": 45
}
```

---

### GET `/api/secretaire/memoires-en-attente/`
🔒 **Secrétaire** — Mémoires non validés.

### POST `/api/secretaire/valider-memoire/{id}/`
🔒 **Secrétaire** — Valider un mémoire (le rendre public).

### POST `/api/secretaire/rejeter-memoire/{id}/`
🔒 **Secrétaire** — Rejeter un mémoire (le supprimer).

### POST `/api/secretaire/creer-compte-etudiant/`
🔒 **Secrétaire** — Créer un compte étudiant temporaire.

**Body** :
```json
{
  "username": "string",
  "password": "string",
  "email": "email",
  "first_name": "string",
  "last_name": "string"
}
```

### GET `/api/secretaire/etudiants-expires/`
🔒 **Secrétaire** — Liste des étudiants expirés.

### POST `/api/secretaire/prolonger-compte/{user_id}/`
🔒 **Secrétaire** — Prolonger de 4 jours.

---

## 8. Étudiant

### GET `/api/etudiant/dashboard/`
🔒 **Étudiant** — Dashboard personnel.

**Réponse 200** :
```json
{
  "mes_memoires": 2,
  "mes_memoires_publics": 1,
  "total_telechargements": 15,
  "jours_restants": 3,
  "date_expiration": "2026-03-28T13:00:00Z",
  "dernier_memoire": { "id": 5, "titre": "..." }
}
```

### GET `/api/etudiant/mes-memoires/`
🔒 **Étudiant** — Ses mémoires.

### POST `/api/etudiant/deposer-memoire/`
🔒 **Étudiant** — Déposer un mémoire (multipart/form-data). Le mémoire est automatiquement mis en attente de validation.

### GET `/api/etudiant/statistiques/`
🔒 **Étudiant** — Statistiques de ses mémoires.

---

## 9. Administration

### POST `/api/admin/creer-admin-entite/`
🔒 **Admin Général** — Créer un admin d'entité.

### POST `/api/admin/creer-secretaire/`
🔒 **Admin Général** — Créer un secrétaire.

### POST `/api/admin/creer-admin-general/`
🔒 **Admin Général** — Créer un autre admin général.

### POST `/api/admin/creer-secretaire-entite/`
🔒 **Admin Entité** — Créer un secrétaire pour son entité.

---

## Rôles et Permissions

| Rôle | Description | Permissions |
|---|---|---|
| `admin_general` | Administrateur global | Accès total à toutes les entités et tous les utilisateurs |
| `admin_entite` | Administrateur d'une entité | Gestion des utilisateurs et mémoires de son entité |
| `secretaire` | Secrétaire d'une entité | Validation des mémoires, gestion des étudiants |
| `etudiant` | Étudiant (compte temporaire 4 jours) | Dépôt et consultation de mémoires |

---

## Codes d'erreur

| Code | Description |
|---|---|
| `200` | Succès |
| `201` | Création réussie |
| `400` | Requête invalide (champs manquants, validation) |
| `401` | Non authentifié |
| `403` | Accès interdit (permissions insuffisantes, compte expiré) |
| `404` | Ressource non trouvée |
| `429` | Trop de requêtes (rate limiting) |
| `500` | Erreur serveur |
