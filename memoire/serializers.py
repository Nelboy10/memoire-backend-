from rest_framework import serializers
from django.contrib.auth.password_validation import validate_password
from .models import User, Entite, Memoire, DownloadLog, Statistiques

class UserSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)
    is_expired = serializers.ReadOnlyField()
    
    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'password', 'first_name', 'last_name', 
                 'role', 'entite', 'date_expiration', 'telephone', 'is_expired', 'is_active']
        read_only_fields = ['date_expiration', 'is_expired']
    
    def create(self, validated_data):
        password = validated_data.pop('password')
        user = User.objects.create_user(**validated_data)
        user.set_password(password)
        user.save()
        return user
    
    def validate_password(self, value):
        validate_password(value)
        return value

class EntiteSerializer(serializers.ModelSerializer):
    administrateur_name = serializers.CharField(source='administrateur.get_full_name', read_only=True)
    
    class Meta:
        model = Entite
        fields = ['id', 'nom', 'description', 'administrateur', 'administrateur_name']

class MemoireSerializer(serializers.ModelSerializer):
    auteur_name = serializers.CharField(source='auteur.get_full_name', read_only=True)
    entite_name = serializers.CharField(source='entite.nom', read_only=True)
    
    class Meta:
        model = Memoire
        fields = ['id', 'titre', 'resume', 'fichier', 'auteur', 'auteur_name', 
                 'entite', 'entite_name', 'est_public', 'nb_telechargements', 
                 'date_soumission', 'annee_soumission', 'filiere', 'mots_cles']
        read_only_fields = ['auteur', 'nb_telechargements', 'date_soumission']

class DownloadLogSerializer(serializers.ModelSerializer):
    memoire_titre = serializers.CharField(source='memoire.titre', read_only=True)
    entite_nom = serializers.CharField(source='entite.nom', read_only=True)
    
    class Meta:
        model = DownloadLog
        fields = ['id', 'email', 'memoire', 'memoire_titre', 'entite', 'entite_nom', 'date_telechargement']

class StatistiquesSerializer(serializers.ModelSerializer):
    entite_nom = serializers.CharField(source='entite.nom', read_only=True)
    
    class Meta:
        model = Statistiques
        fields = ['id', 'entite', 'entite_nom', 'date', 'total_memoires', 
                 'total_telechargements', 'memoires_publics', 'memoires_prives']