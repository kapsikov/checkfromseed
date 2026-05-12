const seedField = document.querySelector('#seed');
const checkButton = document.querySelector('#check');
const result = document.querySelector('#result');
const foundBitcoin = document.querySelector('#found-bitcoin');

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

async function fetchAddressBalanceFromApi(address, apiBaseUrl) {
  const response = await fetch(`${apiBaseUrl}/address/${address}`);
  if (!response.ok) {
    throw new Error(`API error (${response.status}) from ${apiBaseUrl}`);
  }

  const data = await response.json();
  if (!data.chain_stats || !data.mempool_stats) {
    throw new Error(`Unexpected API response for ${address}`);
  }
  const confirmed = data.chain_stats.funded_txo_sum - data.chain_stats.spent_txo_sum;
  const unconfirmed = data.mempool_stats.funded_txo_sum - data.mempool_stats.spent_txo_sum;
  return { confirmed, unconfirmed };
}

function getUserErrorMessage(error) {
  if (!error || !error.message) {
    return 'Unable to check balance right now';
  }

  if (error.message.includes('Invalid seed phrase')) {
    return 'Invalid seed phrase';
  }

  if (error.message.includes('Failed to fetch dynamically imported module')) {
    return 'Unable to load required libraries right now';
  }

  if (error.message.includes('API error (429)')) {
    return 'Rate limited by balance API, please try again shortly';
  }

  if (error.message.includes('API error (5')) {
    return 'Balance API is currently unavailable';
  }

  if (error.message.includes('Failed to fetch')) {
    return 'Network error while contacting balance API';
  }

  return 'Unable to check balance right now';
}

async function fetchAddressBalanceWithFallback(address) {
  const primaryApi = 'https://blockstream.info/api';
  const fallbackApi = 'https://mempool.space/api';

  try {
    return await fetchAddressBalanceFromApi(address, primaryApi);
  } catch (error) {
    console.warn(`Primary API failed for ${address}, trying fallback`, error);
    return fetchAddressBalanceFromApi(address, fallbackApi);
  }
}

async function fetchBalancesWithProgress(addressItems, onProgress) {
  let done = 0;
  const total = addressItems.length;
  const tasks = addressItems.map(async (item) => {
    try {
      const value = await fetchAddressBalanceWithFallback(item.address);
      return { status: 'fulfilled', value };
    } catch (reason) {
      return { status: 'rejected', reason };
    } finally {
      done += 1;
      onProgress(done, total);
    }
  });

  return Promise.all(tasks);
}

async function checkBalance() {
  const phrase = normalizeSeedPhrase(seedField.value);
  result.textContent = 'Checking...';
  foundBitcoin.hidden = true;

  try {
    console.log('Step 1: loading libraries');
    result.textContent = 'Loading libraries...';
    const [bip39, englishWordlistModule, bip32Module, shaModule, ripemdModule, baseModule] = await loadLibs();
    const { validateMnemonic, mnemonicToSeedSync } = bip39;
    const wordlist = englishWordlistModule.wordlist;
    const { HDKey } = bip32Module;
    const hashes = { sha256: shaModule.sha256, ripemd160: ripemdModule.ripemd160 };
    const base = { bech32: baseModule.bech32, base58: baseModule.base58 };

    if (!validateMnemonic(phrase, wordlist)) {
      throw new Error('Invalid seed phrase');
    }

    console.log('Step 2: deriving addresses');
    result.textContent = 'Deriving addresses...';
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
    const settled = await fetchBalancesWithProgress(addressItems, (done, total) => {
      result.textContent = `Checking balances... ${done}/${total}`;
    });

    let confirmedTotal = 0;
    let unconfirmedTotal = 0;
    let failedCount = 0;
    const byPath = {
      BIP84: { confirmed: 0, unconfirmed: 0 },
      BIP49: { confirmed: 0, unconfirmed: 0 },
      BIP44: { confirmed: 0, unconfirmed: 0 }
    };
    const addressesByPath = {
      BIP84: [],
      BIP49: [],
      BIP44: []
    };

    for (let i = 0; i < settled.length; i += 1) {
      const item = settled[i];
      const pathLabel = addressItems[i].label;
      if (item.status === 'fulfilled') {
        confirmedTotal += item.value.confirmed;
        unconfirmedTotal += item.value.unconfirmed;
        byPath[pathLabel].confirmed += item.value.confirmed;
        byPath[pathLabel].unconfirmed += item.value.unconfirmed;
        addressesByPath[pathLabel].push({
          address: addressItems[i].address,
          confirmed: item.value.confirmed,
          unconfirmed: item.value.unconfirmed,
          failed: false
        });
      } else {
        failedCount += 1;
        addressesByPath[pathLabel].push({
          address: addressItems[i].address,
          confirmed: 0,
          unconfirmed: 0,
          failed: true
        });
        console.error('Address fetch failed:', item.reason);
      }
    }

    const fundedAddresses = [];
    let addressesWithoutBalanceSection = 'Addresses without balance\n';
    let addressesWithoutBalance = 0;
    for (let i = 0; i < addressItems.length; i += 1) {
      const item = addressItems[i];
      const balanceResult = settled[i];
      if (balanceResult.status === 'fulfilled') {
        const hasBalance = balanceResult.value.confirmed !== 0 || balanceResult.value.unconfirmed !== 0;
        if (hasBalance) {
          fundedAddresses.push({
            address: item.address,
            label: item.label,
            confirmed: balanceResult.value.confirmed,
            unconfirmed: balanceResult.value.unconfirmed
          });
        } else {
          addressesWithoutBalance += 1;
          addressesWithoutBalanceSection += `Address: ${addressLink(item.address)}\nType: ${item.label}\nConfirmed: ${satoshisToBtc(balanceResult.value.confirmed)} BTC\nUnconfirmed: ${satoshisToBtc(balanceResult.value.unconfirmed)} BTC\n\n`;
        }
      }
    }

    if (addressesWithoutBalance === 0) {
      addressesWithoutBalanceSection += 'No addresses without balance found\n';
    }

    fundedAddresses.sort((a, b) => {
      if (b.confirmed !== a.confirmed) {
        return b.confirmed - a.confirmed;
      }
      return b.unconfirmed - a.unconfirmed;
    });

    const sortedWithoutBalance = [];
    for (let i = 0; i < addressItems.length; i += 1) {
      const balanceResult = settled[i];
      const item = addressItems[i];
      if (balanceResult.status === 'fulfilled' && balanceResult.value.confirmed === 0 && balanceResult.value.unconfirmed === 0) {
        sortedWithoutBalance.push({
          address: item.address,
          label: item.label,
          confirmed: 0,
          unconfirmed: 0
        });
      }
    }

    sortedWithoutBalance.sort((a, b) => a.address.localeCompare(b.address));

    for (const key of ['BIP84', 'BIP49', 'BIP44']) {
      addressesByPath[key].sort((a, b) => {
        if (a.failed && !b.failed) return 1;
        if (!a.failed && b.failed) return -1;
        if (b.confirmed !== a.confirmed) return b.confirmed - a.confirmed;
        return b.unconfirmed - a.unconfirmed;
      });
    }

    let fundedAddressesSection = 'Addresses with balance\n';
    if (fundedAddresses.length === 0) {
      fundedAddressesSection += 'No addresses with balance found\n';
    } else {
      for (const funded of fundedAddresses) {
        fundedAddressesSection += `Address: ${addressLink(funded.address)}\nType: ${funded.label}\nConfirmed: ${satoshisToBtc(funded.confirmed)} BTC\nUnconfirmed: ${satoshisToBtc(funded.unconfirmed)} BTC\n\n`;
      }
    }

    let addressesByPathBIP84 = '';
    for (const entry of addressesByPath.BIP84) {
      if (entry.failed) {
        addressesByPathBIP84 += `${addressLink(entry.address)} | Unable to fetch balance\n`;
      } else {
        addressesByPathBIP84 += `${addressLink(entry.address)} | Confirmed: ${satoshisToBtc(entry.confirmed)} BTC | Unconfirmed: ${satoshisToBtc(entry.unconfirmed)} BTC\n`;
      }
    }

    let addressesByPathBIP49 = '';
    for (const entry of addressesByPath.BIP49) {
      if (entry.failed) {
        addressesByPathBIP49 += `${addressLink(entry.address)} | Unable to fetch balance\n`;
      } else {
        addressesByPathBIP49 += `${addressLink(entry.address)} | Confirmed: ${satoshisToBtc(entry.confirmed)} BTC | Unconfirmed: ${satoshisToBtc(entry.unconfirmed)} BTC\n`;
      }
    }

    let addressesByPathBIP44 = '';
    for (const entry of addressesByPath.BIP44) {
      if (entry.failed) {
        addressesByPathBIP44 += `${addressLink(entry.address)} | Unable to fetch balance\n`;
      } else {
        addressesByPathBIP44 += `${addressLink(entry.address)} | Confirmed: ${satoshisToBtc(entry.confirmed)} BTC | Unconfirmed: ${satoshisToBtc(entry.unconfirmed)} BTC\n`;
      }
    }

    addressesWithoutBalanceSection = 'Addresses without balance\n';
    if (sortedWithoutBalance.length === 0) {
      addressesWithoutBalanceSection += 'No addresses without balance found\n';
    } else {
      for (const item of sortedWithoutBalance) {
        addressesWithoutBalanceSection += `Address: ${addressLink(item.address)}\nType: ${item.label}\nConfirmed: ${satoshisToBtc(item.confirmed)} BTC\nUnconfirmed: ${satoshisToBtc(item.unconfirmed)} BTC\n\n`;
      }
    }

    result.innerHTML = `<div class="left">BIP84<br>Confirmed: ${satoshisToBtc(byPath.BIP84.confirmed)} BTC<br>Unconfirmed: ${satoshisToBtc(byPath.BIP84.unconfirmed)} BTC<br><details><summary>Addresses</summary>${addressesByPathBIP84.replace(/\n/g, '<br>')}</details><br>BIP49<br>Confirmed: ${satoshisToBtc(byPath.BIP49.confirmed)} BTC<br>Unconfirmed: ${satoshisToBtc(byPath.BIP49.unconfirmed)} BTC<br><details><summary>Addresses</summary>${addressesByPathBIP49.replace(/\n/g, '<br>')}</details><br>BIP44<br>Confirmed: ${satoshisToBtc(byPath.BIP44.confirmed)} BTC<br>Unconfirmed: ${satoshisToBtc(byPath.BIP44.unconfirmed)} BTC<br><details><summary>Addresses</summary>${addressesByPathBIP44.replace(/\n/g, '<br>')}</details></div><br><div class="right"><strong>Total</strong><br><strong>Confirmed: ${satoshisToBtc(confirmedTotal)} BTC</strong><br><strong>Unconfirmed: ${satoshisToBtc(unconfirmedTotal)} BTC</strong></div><details open><summary>Addresses with balance</summary><div class="left">${fundedAddressesSection.replace(/\n/g, '<br>')}</div></details><details><summary>Addresses without balance</summary><div class="left">${addressesWithoutBalanceSection.replace(/\n/g, '<br>')}</div></details>`;
    foundBitcoin.hidden = confirmedTotal === 0 && unconfirmedTotal === 0;
    if (failedCount > 0) {
      result.innerHTML += `<br><div class="left">Some address checks failed: ${failedCount}</div>`;
    }
  } catch (error) {
    console.error('Unable to check balance right now');
    console.error(error);
    result.textContent = getUserErrorMessage(error);
    foundBitcoin.hidden = true;
  }
}

checkButton.addEventListener('click', checkBalance);
