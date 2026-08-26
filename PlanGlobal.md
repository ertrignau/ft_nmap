# ft_nmap — Plan global des travaux restants

## Rôle du document

Ce document contient uniquement les chantiers qui restent à terminer pour livrer `ft_nmap`. Il ne redécrit ni le parsing déjà traité séparément, ni les fonctions réseau, builders, checksums, rapports ou outils de laboratoire déjà présents dans le dépôt. Ces éléments ne seront modifiés que lorsque leur interface doit être adaptée au nouveau moteur.

Le détail du runtime, du scheduler, des retries, des timings TCP/UDP et des workers se trouve exclusivement dans **Plan moteur**.

---

## 1. Stabiliser les interfaces entre les modules existants

Figer les structures et fonctions utilisées entre la configuration, les cibles, la préparation réseau, le moteur et l’affichage. L’objectif n’est pas de réécrire les modules existants, mais d’éviter que le nouveau runtime dépende directement des détails du parsing ou de la construction des paquets.

À terminer :

- définir les données exactes fournies au moteur pour chaque cible ;
- définir le format d’un résultat retourné par le moteur ;
- séparer clairement configuration immuable et état runtime ;
- supprimer les anciens champs devenus incompatibles avec la nouvelle architecture.

**Fini lorsque :** le moteur peut être remplacé sans modifier le parser et sans faire dépendre l’affichage des structures internes du scheduler.

---

## 2. Remplacer le runtime actuel par le nouveau moteur

Réécrire la partie `runtime/` autour du scheduler central défini dans **Plan moteur**. Cette étape remplace l’ancienne logique d’envoi, d’attente et d’expiration ; elle ne recrée pas les builders TCP/UDP ni l’ouverture des sockets et de PCAP.

À terminer :

- nouvelles structures de jobs, timings, cibles et scheduler ;
- boucle événementielle centrale ;
- mode sans worker lorsque `--speedup` n’est pas fourni ;
- mode threadé lorsque `--speedup N` est fourni ;
- métriques nécessaires au debug et à la démonstration.

**Fini lorsque :** tous les scans passent par le même scheduler et l’ancien runtime peut être supprimé.

---

## 3. Adapter l’identité et le matching des probes

Le matching existant doit être renforcé pour gérer simultanément plusieurs scans, plusieurs retries, plusieurs cibles et plusieurs processus `ft_nmap`. Cette étape relie les builders déjà présents au nouveau modèle d’identité défini dans **Plan moteur**.

À terminer :

- token TCP définitif ;
- plages ou bases de ports source sûres ;
- matching des réponses TCP directes ;
- matching du paquet original cité dans un ICMP ;
- gestion des réponses tardives ;
- rejet des paquets appartenant à une autre instance du scanner.

**Fini lorsque :** deux scans ou deux processus lancés en parallèle ne peuvent pas récupérer les réponses l’un de l’autre.

---

## 4. Généraliser proprement aux six scans et aux fichiers de cibles

Le moteur doit créer un job pour chaque combinaison `cible × port × scan sélectionné` et exécuter plusieurs cibles sans qu’une cible lente bloque toutes les autres. Les différences entre SYN, ACK, NULL, FIN, XMAS et UDP doivent rester dans les policies de construction et de classification, pas dans six schedulers différents.

À terminer :

- génération complète des jobs ;
- deux timings par cible : TCP et UDP ;
- équité entre les cibles ;
- progression indépendante des groupes TCP et UDP ;
- résultat distinct pour chaque type de scan.

**Fini lorsque :** les combinaisons de scans demandées par la grille fonctionnent sur une cible comme sur un fichier de cibles.

---

## 5. Finaliser la table de résultats et le rapport

Adapter l’affichage existant pour consommer une table de résultats indépendante du runtime. Le rapport doit reprendre exactement les informations observées par la grille sans exposer les structures internes du moteur.

À terminer :

- résultat par cible, port et type de scan ;
- nom standard du service ;
- arguments effectifs utilisés ;
- nombre de ports, scans et threads ;
- durée totale ;
- raisons internes conservées même lorsque `--reason` n’est pas affiché ;
- sortie lisible avec ou sans couleurs et lors d’une redirection.

**Fini lorsque :** les six scans sont clairement identifiables et tous les critères visuels de la grille sont présents.

---

## 6. Rendre l’arrêt et les erreurs totalement propres

Le nouveau moteur ajoute des files, des workers, des pipes et davantage d’états partiels. Le cleanup existant doit être adapté pour rester centralisé et idempotent.

À terminer :

- arrêt pendant `select()` ;
- arrêt pendant des probes en vol ;
- réveil et terminaison des workers ;
- échec partiel de création du pool ;
- fermeture de PCAP, sockets et pipes ;
- destruction des mutex et conditions ;
- libération de toutes les structures runtime.

**Fini lorsque :** le chemin normal, `Ctrl-C` et les principaux chemins d’erreur sont propres sous Valgrind.

---

## 7. Valider le mandatory contre Nmap et la grille

La validation doit porter sur les résultats, les délais, le nombre réel de threads et le comportement sous erreurs. Elle utilise le laboratoire existant et des commandes identiques pour `nmap` et `ft_nmap`.

À terminer :

- scan par défaut des 1024 ports avec les six scans ;
- SYN + NULL avec 200 threads ;
- FIN + XMAS avec 250 threads et plusieurs cibles ;
- ACK + UDP avec 70 threads et plusieurs cibles ;
- `google.fr`, port 79, NULL en moins d’une seconde ;
- `google.fr`, ports 10 à 20, SYN ;
- entrées invalides, fichier vide et bornes de threads ;
- plusieurs instances de `ft_nmap` simultanées ;
- comparaison des résultats et raisons avec le vrai Nmap.

**Fini lorsque :** la correction entière peut être rejouée avec une checklist et aucun test mandatory ne dépend d’un comportement non expliqué.

---

# Bonus retenus

Les bonus commencent uniquement après validation complète du mandatory.

## 8. Bonus — `--open`

Ajouter le vrai flag Nmap `--open`. Le moteur calcule toujours tous les résultats ; le rapport masque seulement les ports qui ne possèdent aucun état potentiellement ouvert.

**Démonstration :** comparer la même cible avec et sans `--open`.

## 9. Bonus — `--reason`

Ajouter le vrai flag Nmap `--reason`. La table de résultats conserve la cause exacte : `syn-ack`, `reset`, `udp-response`, `port-unreachable`, `host-prohibited`, `no-response`, ainsi que les informations ICMP utiles.

**Démonstration :** comparer les raisons affichées avec `nmap --reason`.

## 10. Bonus — Détection de service et de version

Ajouter une phase séparée après le scan de ports. Elle ne s’exécute que sur les ports pertinents, envoie des probes applicatives, lit les bannières et produit un résultat `produit/version` distinct du simple nom de service mandatory.

**Démonstration :** comparer plusieurs services contrôlés avec `nmap -sV`.

## 11. Bonus — Détection indicative de l’OS

Exploiter les informations déjà capturées et quelques probes supplémentaires pour produire un fingerprint : TTL, fenêtre et options TCP, DF, IP ID et comportements ICMP. Le résultat reste une famille probable accompagnée d’un niveau de confiance.

**Démonstration :** différencier plusieurs systèmes du laboratoire sans prétendre reproduire toute la base d’empreintes de Nmap.

## 12. Bonus technique — Moteur centralisé sans pthread

Présenter comme bonus l’architecture dans laquelle `speedup == 0` crée zéro worker, tout en conservant plusieurs probes en vol grâce au scheduler, à PCAP et à `select()`. Le même moteur est ensuite réutilisé avec des workers qui exécutent les envois sans prendre de décision.

**Démonstration :**

- absence de `clone()` worker dans `strace` sans `--speedup` ;
- plusieurs probes simultanément en vol ;
- timing adaptatif TCP/UDP ;
- mêmes résultats avant et après activation des workers ;
- explication de la centralisation de l’état et de l’absence de races.

---

# Ordre de réalisation

1. stabiliser les interfaces ;
2. implémenter **Plan moteur** en mode sans threads ;
3. adapter le matching et les réponses tardives ;
4. ajouter le mode `--speedup N` ;
5. généraliser plusieurs scans et plusieurs cibles ;
6. finaliser résultats, rapport et cleanup ;
7. passer toute la grille ;
8. ajouter `--open` et `--reason` ;
9. ajouter la détection service/version ;
10. ajouter la détection indicative de l’OS.