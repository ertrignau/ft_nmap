FT_NMAP - PARSING TODO
======================

OBJECTIF DU PARSING
-------------------
Le parsing lit uniquement la ligne de commande et remplit config->cli
ainsi que la liste de ports demandee.

Il ne doit pas :
- remettre toute la configuration a zero ;
- initialiser les fd, pcap, la route ou le runtime ;
- resoudre la cible ;
- choisir les valeurs finales du moteur ;
- ouvrir ou analyser completement un fichier de cibles.

Ordre global :
1. nmap_init_config()
2. nmap_parse_cli()
3. nmap_prepare_scan_config()
4. nmap_prepare_target() ou preparation de la liste de cibles
5. nmap_prepare_route()
6. socket / pcap / runtime


============================================================
1. ARGUMENT OBLIGATOIRE POUR LANCER UN SCAN
============================================================

Une source de cible est obligatoire.

Il faut fournir exactement une des deux options suivantes :

[ ] --ip <target>
    Cible unique.
    La valeur peut etre :
    - une IPv4 numerique ;
    - un hostname ;
    - un FQDN.

[ ] --file <path>
    Fichier contenant une liste d'IPv4, hostnames ou FQDN.
    Le format exact du fichier reste libre.

Regles :
- --ip et --file sont mutuellement exclusifs ;
- au moins un des deux est obligatoire ;
- --help peut etre utilise seul, sans --ip ni --file ;
- le parsing verifie seulement la presence et la syntaxe simple ;
- la resolution de la cible appartient a nmap_prepare_target() ;
- le chargement complet du fichier appartient a une preparation dediee.


============================================================
2. OPTIONS OBLIGATOIRES A IMPLEMENTER SELON LE SUJET
   MAIS FACULTATIVES A UTILISER
============================================================

------------------------------------------------------------
2.1 Options avec une valeur
------------------------------------------------------------

[ ] --ports <liste/ranges>

    Exemples :
        --ports 22
        --ports 22,80,443
        --ports 1-1024
        --ports 20-25,53,80,443

    Regles :
    - option facultative ;
    - sans --ports : scanner les ports 1-1024 ;
    - ports valides : 1 a 65535 ;
    - maximum : 1024 ports distincts ;
    - les doublons peuvent etre ignores ;
    - refuser les listes mal formees :
          ,80
          80,
          22,,80
          80-
          -80
          100-20

    Alias actuel :
        --port

    Decision conseillee :
    - garder seulement --ports dans l'interface finale ;
    - supprimer --port ou le conserver uniquement comme alias documente.


[ ] --scan <types>

    Types autorises :
        SYN
        NULL
        ACK
        FIN
        XMAS
        UDP

    L'utilisateur doit pouvoir lancer :
    - un seul type ;
    - plusieurs types simultanement ;
    - tous les types.

    Syntaxe retenue :
        --scan SYN
        --scan SYN,UDP
        --scan SYN,NULL,ACK,FIN,XMAS,UDP

    Regles :
    - option facultative ;
    - sans --scan : activer les six types ;
    - refuser un type inconnu ;
    - refuser les elements vides ;
    - ne pas demander plusieurs occurrences de --scan ;
    - construire un masque avec le OR des types demandes.


[ ] --speedup <0-250>

    Nombre de threads d'envoi.

    Regles :
    - option facultative ;
    - valeur par defaut : 0 ;
    - minimum : 0 ;
    - maximum : 250 ;
    - 0 signifie que le thread principal effectue les envois ;
    - la valeur actuelle 0 doit etre acceptee.

    Erreur actuelle :
    - parse_speedup() refuse 0 ;
    - aucune verification explicite de la limite 250.


------------------------------------------------------------
2.2 Options sans valeur
------------------------------------------------------------

[ ] --help

    Regles :
    - affiche le menu d'aide ;
    - quitte avec succes ;
    - peut etre utilise seul ;
    - ne doit pas exiger --ip, --file ou --ports ;
    - peut etre reconnu avant la validation des arguments obligatoires.


============================================================
3. OPTIONS SUPPLEMENTAIRES RETENUES POUR LE PROJET
============================================================

------------------------------------------------------------
3.1 Options avec une valeur
------------------------------------------------------------

[ ] --retries <nombre>

    Nombre de renvois apres la premiere tentative.

    Semantique :
    - 0 = un seul envoi, aucun retry ;
    - 1 = envoi initial + un retry ;
    - 2 = envoi initial + deux retries.

    Regles :
    - option facultative ;
    - valeur par defaut choisie dans nmap_prepare_scan_config() ;
    - refuser les valeurs negatives ;
    - definir une limite maximale raisonnable.


[ ] --timeout <millisecondes>

    Temps maximal d'attente d'une reponse pour une tentative.

    Regles :
    - option facultative ;
    - valeur strictement positive ;
    - la valeur finale est appliquee dans nmap_prepare_scan_config() ;
    - ce timeout s'applique aux scans TCP et UDP quand il est fourni ;
    - les defaults internes TCP et UDP peuvent rester differents si
      l'utilisateur ne fournit pas ce flag.


[ ] --probes-per-thread <nombre>

    Nombre maximal de probes qu'un thread d'envoi peut avoir
    simultanement en attente de reponse.

    Regles :
    - option facultative ;
    - valeur strictement positive ;
    - valeur par defaut choisie dans nmap_prepare_scan_config() ;
    - le thread principal compte comme un sender quand --speedup vaut 0.

    Capacite globale theorique :
        nombre_de_senders * probes_per_thread

    Avec --speedup 0 :
        nombre_de_senders = 1

    Avec --speedup N :
        nombre_de_senders = N

    Exemple :
        --speedup 10 --probes-per-thread 1
        environ 10 probes simultanement en l'air.

        --speedup 10 --probes-per-thread 50
        jusqu'a environ 500 probes simultanement en l'air.

    Le scheduler reste responsable de la vraie limite globale et les retries
    doivent respecter cette meme capacite.


------------------------------------------------------------
3.2 Options sans valeur
------------------------------------------------------------

[ ] --no-dns

    Desactive le reverse DNS et l'affichage du hostname retrouve depuis une IP.

    Attention :
    - ce flag ne doit pas empecher de resoudre une cible fournie sous forme
      de hostname ou de FQDN ;
    - la resolution directe reste necessaire pour obtenir l'IPv4 a scanner.


[ ] --version

    Active la detection du produit et de sa version sur les ports ouverts.

    Attention :
    - la resolution du TYPE de service est obligatoire selon le sujet ;
    - elle doit fonctionner meme sans --version ;
    - --version ajoute seulement une detection plus detaillee.

    Exemple sans --version :
        22/tcp open ssh

    Exemple avec --version :
        22/tcp open ssh OpenSSH 9.x


[ ] --os

    Active la phase de detection d'OS.


[ ] --open

    Affiche uniquement les ports ayant au moins un resultat :
    - open ;
    - open|filtered.

    Attention :
    - le champ actuel hide_uninteresting n'a pas exactement cette semantique ;
    - le rapport actuel peut encore conserver des ports seulement filtered ;
    - un vrai mode --open doit etre distingue de hide_uninteresting.


[ ] --reason

    Affiche la raison de chaque resultat.

    Exemples :
        syn-ack
        reset
        udp-response
        icmp-port-unreachable
        icmp-host-prohibited
        no-response


============================================================
4. FONCTIONNALITE OBLIGATOIRE SANS FLAG
============================================================

La resolution du TYPE de service est demandee par le sujet.

Elle doit etre automatique et ne depend pas de --version.

Exemples :
    21/tcp   ftp
    22/tcp   ssh
    53/udp   domain
    80/tcp   http
    443/tcp  https

Cette resolution peut utiliser :
- une table interne ;
- getservbyport() ;
- une autre methode retenue par le projet.

--version correspond au bonus de detection du produit et de sa version,
pas a la simple resolution du type de service.


============================================================
5. CE QUI EST DEJA PARSE
============================================================

Le parsing actuel gere deja :
- --ip <target>
- --ports <liste/ranges>
- --port <liste/ranges>
- --scan <type unique>
- --speedup <nombre>

Il reste a adapter ces options aux regles ci-dessus et a ajouter :
- --file
- --help
- --retries
- --timeout
- --probes-per-thread
- --no-dns
- --version
- --os
- --open
- --reason


============================================================
6. CORRECTIONS A FAIRE DANS LE PARSING ACTUEL
============================================================

[ ] Supprimer init_client() du parsing.

    nmap_init_config() initialise deja toute la structure avant
    nmap_parse_cli().


[ ] Ne jamais faire dans nmap_parse_cli() :

        memset(config, 0, sizeof(*config));


[ ] Ne pas remettre les valeurs par defaut dans config->cli.

    Apres le memset de nmap_init_config(), une valeur CLI a zero signifie :
    option non fournie.


[ ] Supprimer a la fin de nmap_parse_cli() :

        config->scan.scan_mask = config->cli.scan_mask;

    La construction de la configuration effective appartient a
    nmap_prepare_scan_config().


[ ] Modifier check_required_args().

    Actuellement il exige :
    - --ip ;
    - --ports.

    Nouveau comportement :
    - exiger exactement une source entre --ip et --file ;
    - ne plus exiger --ports ;
    - ne rien exiger lorsque --help est present.


[ ] Modifier parse_scan().

    Actuellement il accepte un seul type.
    Il doit accepter une liste separee par des virgules.


[ ] Modifier parse_speedup().

    Il doit accepter 0 et refuser les valeurs superieures a 250.


[ ] Rendre le parsing des listes strict.

    strtok_r() ignore certains champs vides.
    Il faut donc verifier explicitement les virgules mal placees avant
    ou pendant le decoupage.


[ ] Utiliser des limites adaptees a chaque option.

    nmap_parse_int() accepte actuellement 0 a 65535.
    Cela ne suffit pas comme validation finale pour toutes les options :

    - speedup : 0 a 250 ;
    - port : 1 a 65535 ;
    - retries : plage specifique ;
    - timeout : strictement positif ;
    - probes-per-thread : strictement positif.


============================================================
7. RESPONSABILITES DU PARSING ET DES PREPARATIONS
============================================================

Le parsing verifie :
- que le flag existe ;
- que son argument existe quand il en faut un ;
- que la syntaxe est valide ;
- que la valeur respecte la plage du flag ;
- qu'un flag non repetable n'est pas donne plusieurs fois ;
- que --ip et --file ne sont pas utilises ensemble.

nmap_prepare_scan_config() decide :
- les ports par defaut 1-1024 ;
- les six scans par defaut ;
- le nombre effectif de threads ;
- le nombre de retries par defaut ;
- les timeouts effectifs ;
- les probes par thread ;
- les limites globales derivees pour le scheduler.

nmap_prepare_target() decide :
- si la cible est une IPv4 valide ;
- si un hostname ou FQDN peut etre resolu ;
- quelle IPv4 est finalement scannee.

La preparation du fichier decide :
- si le fichier peut etre ouvert ;
- quelles lignes sont valides ;
- quelles cibles sont chargees ;
- comment les erreurs de lignes sont traitees.

nmap_prepare_route() decide :
- l'interface de sortie ;
- l'adresse IPv4 source.


============================================================
8. REGLES SUR LES DOUBLONS
============================================================

Options avec une valeur :
- --ip
- --file
- --ports
- --scan
- --speedup
- --retries
- --timeout
- --probes-per-thread

Decision retenue :
- une seule occurrence de chaque option ;
- une repetition est une erreur ;
- --ip et --file sont mutuellement exclusifs.


Options booleennes :
- --help
- --no-dns
- --version
- --os
- --open
- --reason

Decision retenue :
- une repetition peut rester idempotente ;
- elle ne change pas le resultat.


============================================================
9. CHAMPS CLI A VERIFIER
============================================================

Les champs suivants existent deja :
- help
- no_dns
- speedup
- timeout_ms
- max_in_flight
- scan_mask
- scan_specified
- hide_uninteresting

Points a revoir :
- max_in_flight ne represente pas clairement une limite par thread ;
- ajouter un champ explicite probes_per_thread ;
- ajouter retries ;
- ajouter version_detection ;
- ajouter os_detection ;
- ajouter open_only ;
- ajouter show_reason ;
- ajouter file_path ou une structure de source de cibles.

hide_uninteresting et open_only ne doivent pas etre confondus.

Les champs :
- error
- cli_error

semblent faire doublon.

Les champs :
- bad_arg
- bad_index

ne sont utiles que si les erreurs sont stockees puis affichees plus tard.
Si les erreurs sont affichees immediatement, ils peuvent etre supprimes.


============================================================
10. EXEMPLES DE COMMANDES ATTENDUES
============================================================

Cible unique, defaults :
    ./ft_nmap --ip 172.28.0.10

Equivalent attendu :
- ports 1-1024 ;
- six types de scan ;
- speedup 0 ;
- valeurs moteur par defaut.


Plusieurs scans :
    ./ft_nmap --ip example.com --scan SYN,UDP


Ports particuliers :
    ./ft_nmap --ip 172.28.0.10 --ports 22,53,80,443


Configuration du moteur :
    ./ft_nmap --ip 172.28.0.10 \
        --speedup 10 \
        --probes-per-thread 50 \
        --retries 2 \
        --timeout 1000


Liste de cibles :
    ./ft_nmap --file targets.txt --scan SYN --ports 1-1024


Bonus :
    ./ft_nmap --ip example.com --version --os --reason --open


Aide :
    ./ft_nmap --help
