const seedField = document.querySelector('#seed');
const checkButton = document.querySelector('#check');
const result = document.querySelector('#result');

let libsPromise;

function loadLibs() {
  if (!libsPromise) {
    libsPromise = Promise.all([
      import('https://esm.sh/@scure/bip39@1.3.0'),
      import('https://esm.sh/@scure/bip39@1.3.0/wordlists/english'),
      import('https://esm.sh/@scure/bip32@1.4.0'),
      import('https://esm.sh/@noble/hashes@1.5.0/sha256'),
      import('https://esm.sh/@noble/hashes@1.5.0/ripemd160'),
      import('https://esm.sh/@scure/base@1.1.9')
    ]);
  }

  return libsPromise;
}

function normalizeSeedPhrase(value) {
  return value.trim().toLowerCase().replace(/\s+/g, ' ');
}

function satoshisToBtc(value) {
  return (value / 100000000).toFixed(8);
}

function addressLink(address) {
  return `<a href="https://blockstream.info/address/${address}" target="_blank" rel="noopener noreferrer">${address}</a>`;
}

function concatBytes(...arrays) {
  let totalLength = 0;
  for (const arr of arrays) {
    totalLength += arr.length;
  }

  const resultBytes = new Uint8Array(totalLength);
  let offset = 0;
  for (const arr of arrays) {
    resultBytes.set(arr, offset);
    offset += arr.length;
  }

  return resultBytes;
}

function toBase58Check(payload, hashes, base) {
  const checksum = hashes.sha256(hashes.sha256(payload)).slice(0, 4);
  return base.base58.encode(concatBytes(payload, checksum));
}

function deriveAddress(root, pathPrefix, change, index, type, hashes, base) {
  const path = `${pathPrefix}/${change}/${index}`;
  const child = root.derive(path);
  const pubkeyHash = hashes.ripemd160(hashes.sha256(child.publicKey));

  if (type === 'bip84') {
    const words = base.bech32.toWords(pubkeyHash);
    words.unshift(0);
    return base.bech32.encode('bc', words);
  }

  if (type === 'bip49') {
    const redeemScript = concatBytes(new Uint8Array([0x00, 0x14]), pubkeyHash);
    const scriptHash = hashes.ripemd160(hashes.sha256(redeemScript));
    return toBase58Check(concatBytes(new Uint8Array([0x05]), scriptHash), hashes, base);
  }

  return toBase58Check(concatBytes(new Uint8Array([0x00]), pubkeyHash), hashes, base);
}

async function fetchAddressBalance(address) {
  const response = await fetch(`https://blockstream.info/api/address/${address}`);
  if (!response.ok) {
    throw new Error('Failed to fetch address data');
  }

  const data = await response.json();
  if (!data.chain_stats || !data.mempool_stats) {
    throw new Error(`Unexpected API response for ${address}`);
  }
  const confirmed = data.chain_stats.funded_txo_sum - data.chain_stats.spent_txo_sum;
  const unconfirmed = data.mempool_stats.funded_txo_sum - data.mempool_stats.spent_txo_sum;
  return { confirmed, unconfirmed };
}

async function checkBalance() {
  const phrase = normalizeSeedPhrase(seedField.value);
  result.textContent = 'Checking...';

  try {
    console.log('Step 1: loading libraries');
    const [bip39, englishWordlistModule, bip32Module, shaModule, ripemdModule, baseModule] = await loadLibs();
    const { validateMnemonic, mnemonicToSeedSync } = bip39;
    const wordlist = englishWordlistModule.wordlist;
    const { HDKey } = bip32Module;
    const hashes = { sha256: shaModule.sha256, ripemd160: ripemdModule.ripemd160 };
    const base = { bech32: baseModule.bech32, base58: baseModule.base58 };

    if (!validateMnemonic(phrase, wordlist)) {
      result.textContent = 'Invalid seed phrase';
      return;
    }

    console.log('Step 2: deriving addresses');
    const seed = mnemonicToSeedSync(phrase);
    const root = HDKey.fromMasterSeed(seed);
    const derivationPaths = [
      { label: 'BIP84', prefix: "m/84'/0'/0'", type: 'bip84' },
      { label: 'BIP49', prefix: "m/49'/0'/0'", type: 'bip49' },
      { label: 'BIP44', prefix: "m/44'/0'/0'", type: 'bip44' }
    ];
    const depth = 5;
    const addressItems = [];

    for (const pathConfig of derivationPaths) {
      for (let i = 0; i < depth; i += 1) {
        addressItems.push({
          label: pathConfig.label,
          address: deriveAddress(root, pathConfig.prefix, 0, i, pathConfig.type, hashes, base)
        });
        addressItems.push({
          label: pathConfig.label,
          address: deriveAddress(root, pathConfig.prefix, 1, i, pathConfig.type, hashes, base)
        });
      }
    }

    console.log(`Step 3: fetching balances for ${addressItems.length} addresses`);
    const settled = await Promise.allSettled(addressItems.map((item) => fetchAddressBalance(item.address)));

    let confirmedTotal = 0;
    let unconfirmedTotal = 0;
    let failedCount = 0;
    const byPath = {
      BIP84: { confirmed: 0, unconfirmed: 0 },
      BIP49: { confirmed: 0, unconfirmed: 0 },
      BIP44: { confirmed: 0, unconfirmed: 0 }
    };
    const addressesByPath = {
      BIP84: '',
      BIP49: '',
      BIP44: ''
    };

    for (let i = 0; i < settled.length; i += 1) {
      const item = settled[i];
      const pathLabel = addressItems[i].label;
      if (item.status === 'fulfilled') {
        confirmedTotal += item.value.confirmed;
        unconfirmedTotal += item.value.unconfirmed;
        byPath[pathLabel].confirmed += item.value.confirmed;
        byPath[pathLabel].unconfirmed += item.value.unconfirmed;
        addressesByPath[pathLabel] += `${addressLink(addressItems[i].address)} | Confirmed: ${satoshisToBtc(item.value.confirmed)} BTC | Unconfirmed: ${satoshisToBtc(item.value.unconfirmed)} BTC\n`;
      } else {
        failedCount += 1;
        addressesByPath[pathLabel] += `${addressLink(addressItems[i].address)} | Unable to fetch balance\n`;
        console.error('Address fetch failed:', item.reason);
      }
    }

    let addressesWithBalanceSection = 'Addresses with balance\n';
    let addressesWithoutBalanceSection = 'Addresses without balance\n';
    let addressesWithBalance = 0;
    let addressesWithoutBalance = 0;
    for (let i = 0; i < addressItems.length; i += 1) {
      const item = addressItems[i];
      const balanceResult = settled[i];
      if (balanceResult.status === 'fulfilled') {
        const hasBalance = balanceResult.value.confirmed !== 0 || balanceResult.value.unconfirmed !== 0;
        if (hasBalance) {
          addressesWithBalance += 1;
          addressesWithBalanceSection += `Address: ${addressLink(item.address)}\nType: ${item.label}\nConfirmed: ${satoshisToBtc(balanceResult.value.confirmed)} BTC\nUnconfirmed: ${satoshisToBtc(balanceResult.value.unconfirmed)} BTC\n\n`;
        } else {
          addressesWithoutBalance += 1;
          addressesWithoutBalanceSection += `Address: ${addressLink(item.address)}\nType: ${item.label}\nConfirmed: ${satoshisToBtc(balanceResult.value.confirmed)} BTC\nUnconfirmed: ${satoshisToBtc(balanceResult.value.unconfirmed)} BTC\n\n`;
        }
      }
    }

    if (addressesWithBalance === 0) {
      addressesWithBalanceSection += 'No addresses with balance found\n';
    }

    if (addressesWithoutBalance === 0) {
      addressesWithoutBalanceSection += 'No addresses without balance found\n';
    }

    result.innerHTML = `<div class="left">BIP84<br>Confirmed: ${satoshisToBtc(byPath.BIP84.confirmed)} BTC<br>Unconfirmed: ${satoshisToBtc(byPath.BIP84.unconfirmed)} BTC<br><details><summary>Addresses</summary>${addressesByPath.BIP84.replace(/\n/g, '<br>')}</details><br>BIP49<br>Confirmed: ${satoshisToBtc(byPath.BIP49.confirmed)} BTC<br>Unconfirmed: ${satoshisToBtc(byPath.BIP49.unconfirmed)} BTC<br><details><summary>Addresses</summary>${addressesByPath.BIP49.replace(/\n/g, '<br>')}</details><br>BIP44<br>Confirmed: ${satoshisToBtc(byPath.BIP44.confirmed)} BTC<br>Unconfirmed: ${satoshisToBtc(byPath.BIP44.unconfirmed)} BTC<br><details><summary>Addresses</summary>${addressesByPath.BIP44.replace(/\n/g, '<br>')}</details></div><br><div class="right"><strong>Total</strong><br><strong>Confirmed: ${satoshisToBtc(confirmedTotal)} BTC</strong><br><strong>Unconfirmed: ${satoshisToBtc(unconfirmedTotal)} BTC</strong></div><details open><summary>Addresses with balance</summary><div class="left">${addressesWithBalanceSection.replace(/\n/g, '<br>')}</div></details><details><summary>Addresses without balance</summary><div class="left">${addressesWithoutBalanceSection.replace(/\n/g, '<br>')}</div></details>`;
    if (failedCount > 0) {
      result.innerHTML += `<br><div class="left">Some address checks failed: ${failedCount}</div>`;
    }
  } catch (error) {
    console.error('Unable to check balance right now');
    console.error(error);
    result.textContent = 'Unable to check balance right now';
  }
}

checkButton.addEventListener('click', checkBalance);
