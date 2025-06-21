import {split, combine} from 'shamir-secret-sharing';

const toUint8Array = (data) => new TextEncoder().encode(data);

async function main() {
  const input = '0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef';
  const secret = toUint8Array(input);
  const [share1, share2, share3] = await split(secret, 3, 2);

  const reconstructed1 = await combine([share1, share2]);
  const reconstructed2 = await combine([share1, share3]);
  const reconstructed3 = await combine([share2, share3]);
  const reconstructed4 = await combine([share1, share2, share3]);

  console.log(new TextDecoder().decode(reconstructed1));
  console.log(new TextDecoder().decode(reconstructed2));
  console.log(new TextDecoder().decode(reconstructed3));
  console.log(new TextDecoder().decode(reconstructed4));
  console.log(new TextDecoder().decode(secret));

  try {
    const reconstructed5 = await combine([share1]); // exception expected
    console.log(new TextDecoder().decode(reconstructed5)); // Should throw an error  
  } catch (error) {
    console.error(error);
  }
  
}

main();