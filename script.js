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

function deriveAddress(root, change, index, hashes, base) {
  const path = `m/84'/0'/0'/${change}/${index}`;
  const child = root.derive(path);
  const pubkeyHash = hashes.ripemd160(hashes.sha256(child.publicKey));
  const words = base.bech32.toWords(pubkeyHash);
  words.unshift(0);
  return base.bech32.encode('bc', words);
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
    const base = { bech32: baseModule.bech32 };

    if (!validateMnemonic(phrase, wordlist)) {
      result.textContent = 'Invalid seed phrase';
      return;
    }

    console.log('Step 2: deriving addresses');
    const seed = mnemonicToSeedSync(phrase);
    const root = HDKey.fromMasterSeed(seed);
    const addresses = [];

    for (let i = 0; i < 5; i += 1) {
      addresses.push(deriveAddress(root, 0, i, hashes, base));
      addresses.push(deriveAddress(root, 1, i, hashes, base));
    }

    console.log(`Step 3: fetching balances for ${addresses.length} addresses`);
    const settled = await Promise.allSettled(addresses.map(fetchAddressBalance));

    let confirmedTotal = 0;
    let unconfirmedTotal = 0;
    let failedCount = 0;

    for (const item of settled) {
      if (item.status === 'fulfilled') {
        confirmedTotal += item.value.confirmed;
        unconfirmedTotal += item.value.unconfirmed;
      } else {
        failedCount += 1;
        console.error('Address fetch failed:', item.reason);
      }
    }

    result.textContent = `Confirmed: ${satoshisToBtc(confirmedTotal)} BTC\nUnconfirmed: ${satoshisToBtc(unconfirmedTotal)} BTC`;
    if (failedCount > 0) {
      result.textContent += `\nSome address checks failed: ${failedCount}`;
    }
  } catch (error) {
    console.error('Unable to check balance right now');
    console.error(error);
    result.textContent = 'Unable to check balance right now';
  }
}

checkButton.addEventListener('click', checkBalance);
