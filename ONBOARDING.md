# SuVa Protocol — Guide d'onboarding complet

**Auteur :** Mohamed Lamine MBENGUE
**Projet :** SuVa Protocol — Signatures post-quantiques sur Ethereum
**Dernière mise à jour :** Avril 2026

---

## 1. C'est quoi SuVa ?

SuVa est un protocole qui permet de signer des transactions Ethereum avec des algorithmes **résistants aux ordinateurs quantiques**.

Le problème qu'on résout :
- Ethereum utilise ECDSA pour signer les transactions
- Un ordinateur quantique suffisamment puissant peut casser ECDSA
- On intègre des signatures **post-quantiques** (Falcon, SPHINCS+) directement dans les contrats Solidity

**En résumé :** SuVa = Ethereum + sécurité post-quantique, sans modifier le protocole Ethereum lui-même.

---

## 2. Les 4 phases du projet

| Phase | Ce qu'on a fait | Fichiers clés |
|---|---|---|
| **Phase 1** | Implémenter le vérifieur Dilithium en Solidity + Yul | `ZKNOX_dilithium.sol` |
| **Phase 2** | Implémenter ETHFalcon (Falcon avec Keccak au lieu de SHAKE) | `ZKNOX_ethfalcon.sol` + Python |
| **Phase 3** | QuantumVault : dépôt/retrait d'USDT protégé par signature Falcon | `QuantumVault.sol`, `qUSDT.sol` |
| **Phase 4** | SuVaWallet ERC-4337 : portefeuille avec double signature ECDSA + Falcon | `SuVaWallet.sol`, `SuVaWalletFactory.sol` |

**Phase 5 (à venir) :** SPHINCS+ — étude de faisabilité + PoC, dans la direction EIP-8141.

---

## 3. Stack technique — ce qu'il faut maîtriser

### 3.1 Python (base du projet)

Ce qu'on utilise Python pour :
- Générer des clés Falcon et signer des messages
- Générer les vecteurs de test pour Solidity (fichiers `.t.sol`)
- Vérifier les signatures côté Python avant de les tester on-chain

**Bibliothèques à connaître :**
```bash
pip install falcon-py   # implémentation NIST de Falcon
pip install pytest      # pour lancer les tests Python
```

**Commandes utiles :**
```bash
# Lancer les tests Python
cd falcon_dilithium/ETHDILITHIUM-main/python-ref/
python -m pytest -v

# Générer les vecteurs de test Falcon
python -m Falcon_dilithium_py.generate_falcon_test_vectors
```

**Niveau requis :** Python intermédiaire — tu dois savoir lire et modifier des classes, gérer des bytes, appeler des bibliothèques.

---

### 3.2 Solidity (contrats intelligents)

Solidity = langage pour écrire des contrats sur Ethereum. Pense à Python mais pour la blockchain.

**Ce qu'on a écrit en Solidity :**

| Fichier | Rôle |
|---|---|
| `ZKNOX_ethfalcon.sol` | Vérifie une signature Falcon on-chain |
| `QuantumVault.sol` | Coffre-fort USDT sécurisé par Falcon |
| `qUSDT.sol` | Token ERC-20 reçu quand on dépose dans le vault |
| `SuVaWallet.sol` | Portefeuille ERC-4337 avec double signature |
| `SuVaWalletFactory.sol` | Déploie des wallets SuVa avec CREATE2 |
| `IFalconVerifier.sol` | Interface commune pour le vérifieur Falcon |

**Ce qu'il faut comprendre en Solidity :**
- `interface` : définit ce qu'un contrat doit exposer (comme un contrat/protocole)
- `modifier` : vérifie une condition avant d'exécuter une fonction
- `event` : journal d'actions lisible depuis l'extérieur
- `calldata` / `memory` / `storage` : où les données sont stockées (impacte le gas)
- `payable` : une fonction qui peut recevoir de l'ETH

**Tu n'as pas besoin de tout coder toi-même** — tu dois comprendre ce que le code fait et être capable de l'expliquer.

---

### 3.3 Foundry (tests et déploiement)

Foundry = outil pour compiler, tester et déployer des contrats Solidity.

**Commandes essentielles :**
```bash
# Compiler les contrats
forge build

# Lancer tous les tests
forge test -vv

# Lancer les tests avec rapport de gas
forge test -vv --gas-report

# Déployer sur Sepolia (testnet)
forge script script/DeploySuVa.s.sol \
  --rpc-url https://ethereum-sepolia-rpc.publicnode.com \
  --private-key TON_PRIVATE_KEY \
  --broadcast

# Vérifier un contrat sur Etherscan
forge verify-contract ADRESSE src/NomContrat.sol:NomContrat \
  --chain-id 11155111 \
  --etherscan-api-key TA_CLE_API \
  --watch
```

**Profils de test :**
```bash
# Tests rapides (sans optimiseur — pour développement)
FOUNDRY_PROFILE=lite forge test -vv

# Tests avec optimiseur (pour mesures de gas réelles)
forge test -vv
```

---

### 3.4 Cryptographie post-quantique — concepts clés

Tu n'as pas besoin d'être mathématicien. Voici ce qu'il faut vraiment comprendre :

#### Falcon-256
- **Ce que c'est :** Algorithme de signature post-quantique basé sur les réseaux euclidiens (NTRU lattices)
- **Clé publique `h` :** Polynôme de 256 coefficients dans Z_12289
- **Signature :** nonce (40 octets) + vecteur s2 encodé
- **Vérification :** calculer `s1 = HashToPoint(nonce||msg) - h*s2`, vérifier que `||s1||² + ||s2||²  ≤ β²`
- **Pourquoi Falcon :** signatures courtes (~333 octets), efficace pour Ethereum

#### ETHFalcon vs Falcon standard
| | Falcon standard | ETHFalcon |
|---|---|---|
| Fonction de hachage | SHAKE-256 | Keccak-256 |
| Raison | NIST standard | Keccak = natif EVM, moins de gas |

#### ECDSA (signature classique d'Ethereum)
- Basé sur la courbe elliptique secp256k1
- Vulnérable aux ordinateurs quantiques (algorithme de Shor)
- On le garde pour la compatibilité, on ajoute Falcon en plus (double signature)

#### Double signature (Phase 4)
```
UserOperation.signature = ECDSA_sig (65 octets) || abi.encode(h, salt, s1)
                          ↑ classique                ↑ post-quantique
```
Les deux doivent être valides pour exécuter une transaction.

---

### 3.5 ERC-4337 — Account Abstraction

**Le problème :** Sur Ethereum, un "compte" normal (EOA) est lié à une clé ECDSA. Impossible d'utiliser autre chose.

**La solution ERC-4337 :** Un contrat intelligent peut jouer le rôle de compte si il implémente `validateUserOp()`.

**Composants ERC-4337 :**

| Composant | Rôle |
|---|---|
| `UserOperation` | La "transaction" envoyée par l'utilisateur |
| `EntryPoint` | Contrat officiel qui orchestre tout (`0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789`) |
| `Bundler` | Service qui regroupe les UserOps et les soumet à l'EntryPoint |
| `SuVaWallet` | Notre contrat-compte, implémente `validateUserOp()` |

**Flux d'une transaction SuVaWallet :**
```
Utilisateur → signe avec ECDSA + Falcon
    → envoie UserOperation au Bundler
    → Bundler appelle EntryPoint
    → EntryPoint appelle SuVaWallet.validateUserOp()
    → Si valide → SuVaWallet.execute()
```

**EIP-8141 (futur) :** Intègre cette logique directement dans le protocole Ethereum, sans Bundler. SuVa sera compatible.

---

### 3.6 Ethereum Sepolia (testnet)

Sepolia = réseau de test Ethereum gratuit pour déployer sans risque.

**Adresses des contrats déployés :**

| Phase | Contrat | Adresse Sepolia |
|---|---|---|
| Phase 2/3 | ZKNOX_ethfalcon | `0xa6279c2ce813306da0f7b81e434e4a88f0b25626` |
| Phase 3 | MockUSDT | `0xf088bc3f822ee138753afe3190d1adec60abbaf3` |
| Phase 3 | qUSDT | `0xf8f3009c473d538da9b188f33bd6a6cbead29902` |
| Phase 3 | QuantumVault | `0x601cd837e9edd0dfb311ff1a48ed7bea7bbaf1c4` |
| Phase 4 | SuVaWalletFactory | `0x716a0C550eC1267Db493515d4a114C2FCf942e6B` |
| Phase 4 | SuVaWallet | `0x8a907C21014ED2926a53b4d18eC6e1b8C5a514cE` |
| - | EntryPoint ERC-4337 | `0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789` |

Tous les contrats sont **vérifiés sur Etherscan** (code source public).

**Pour obtenir des ETH Sepolia gratuits :**
- `sepoliafaucet.com`
- `faucet.quicknode.com/ethereum/sepolia`

---

## 4. Structure du projet

```
d:\Projects\suva\
├── ONBOARDING.md                    ← ce fichier
├── rapports\
│   ├── rapport_phase3_EN.tex        ← rapport Phase 3 (anglais)
│   ├── rapport_phase3_FR.tex        ← rapport Phase 3 (français)
│   ├── rapport_phase4_EN.tex        ← rapport Phase 4 (anglais)
│   └── rapport_phase4_FR.tex        ← rapport Phase 4 (français)
└── falcon_dilithium\
    └── ETHDILITHIUM-main\
        ├── src\
        │   ├── IFalconVerifier.sol      ← interface commune
        │   ├── ZKNOX_ethfalcon.sol      ← vérifieur Falcon on-chain
        │   ├── QuantumVault.sol         ← Phase 3
        │   ├── qUSDT.sol                ← Phase 3
        │   ├── MockERC20.sol            ← Phase 3 (USDT simulé)
        │   ├── SuVaWallet.sol           ← Phase 4
        │   └── SuVaWalletFactory.sol    ← Phase 4
        ├── test\
        │   ├── QuantumVault.t.sol       ← 26 tests Phase 3
        │   └── SuVaWallet.t.sol         ← 15 tests Phase 4
        ├── script\
        │   └── DeploySuVa.s.sol         ← script de déploiement complet
        ├── python-ref\
        │   └── Falcon_dilithium_py\
        │       ├── Falcon_falcon\       ← module Python ETHFalcon
        │       └── generate_falcon_test_vectors.py
        └── foundry.toml                 ← configuration Foundry
```

---

## 5. Tests — état actuel

```bash
forge test -vv
# Résultat : 41/41 tests passants (0 échec)
```

| Suite | Tests | Couverture |
|---|---|---|
| `QuantumVault.t.sol` | 26 | Dépôt, retrait, signature Falcon, sécurité |
| `SuVaWallet.t.sol` | 15 | Déploiement, registration clé, validateUserOp, execute, factory |

---

## 6. Interface publique SuVa (pour BTQ / interopérabilité)

L'interface centrale à standardiser avec BTQ :

```solidity
// IFalconVerifier.sol — interface commune
interface IFalconVerifier {
    function verify(
        uint256[256] calldata h,      // clé publique (256 coefficients)
        bytes        calldata salt,   // nonce/salt de la signature
        uint256[256] calldata s1,     // vecteur s1
        bytes        calldata message // message signé
    ) external pure returns (bool);
}
```

Cette interface permet à n'importe quel contrat (QuantumVault, SuVaWallet, ou un futur contrat BTQ) d'utiliser le même vérifieur Falcon, quelle que soit l'implémentation derrière.

---

## 7. Collaboration BTQ — contexte

**BTQ** est une startup post-quantique blockchain. Leur protocole s'appelle **QSSN** (Quantum Safe Signature Network).

**Points d'alignement avec SuVa :**
- Même objectif : assets et stablecoins quantum-safe sur Ethereum sans modifier le protocole
- Même approche : wrapping d'assets existants avec signature PQC
- Piste commune : soumettre un EIP conjoint pour un standard Ethereum quantum-safe

**EIP-8141** (publié avril 2026, auteurs : Vitalik Buterin et al.) :
- Propose d'intégrer l'abstraction de compte directement dans le protocole
- Permet les signatures PQC nativement, sans Bundler ERC-4337
- SuVa Phase 4 est un précurseur direct de cette vision

---

## 8. Lexique rapide

| Terme | Définition simple |
|---|---|
| **EOA** | Compte Ethereum classique lié à une clé ECDSA |
| **Smart contract** | Programme qui tourne sur la blockchain Ethereum |
| **Gas** | Coût de calcul d'une opération sur Ethereum (payé en ETH) |
| **ERC-20** | Standard pour les tokens fongibles (USDT, USDC...) |
| **ERC-4337** | Standard pour les comptes-contrats avec validation custom |
| **Lattice** | Structure mathématique utilisée par Falcon (réseaux euclidiens) |
| **NTT** | Transformation de Fourier sur corps fini — accélère la multiplication polynomiale |
| **Bundler** | Service qui regroupe les UserOps et les soumet à l'EntryPoint |
| **Sepolia** | Réseau de test Ethereum (gratuit, pas de vrai argent) |
| **Etherscan** | Explorateur blockchain — voir les contrats, transactions, code source |
| **CREATE2** | Déploiement de contrat à adresse déterministe (même adresse à chaque fois) |
| **SPHINCS+** | Algorithme de signature post-quantique basé sur les fonctions de hachage (Phase 5) |

---

## 9. Par où commencer ?

Si tu arrives sur ce projet pour la première fois :

1. **Lire** ce document en entier
2. **Installer** Foundry : `curl -L https://foundry.paradigm.xyz | bash && foundryup`
3. **Cloner** et compiler : `forge build`
4. **Lancer** les tests : `forge test -vv` — tout doit passer en vert
5. **Lire** `src/SuVaWallet.sol` — c'est le cœur de la Phase 4
6. **Lire** `src/IFalconVerifier.sol` — c'est l'interface d'interopérabilité avec BTQ
