export const SEPOLIA_CHAIN_ID = 11155111;

export type DemoAddresses = {
  pool: `0x${string}`;
  recipientRegistry: `0x${string}`;
  authVerifier: `0x${string}`;
};

export const demoAddresses: DemoAddresses = {
  pool: '0x61C1c7fad998EB9b772fB6479563524355353589',
  recipientRegistry: '0xbeb7B031Ee35525Cf96a389b1C1e04213D01E786',
  authVerifier: '0x85FD1f12299d26d9572fD7c1Dd5D4E95B2c5EF17',
};

export const deploymentBlock = 11130601n;

export function addressesConfigured(addresses = demoAddresses): boolean {
  return [addresses.pool, addresses.recipientRegistry].every(
    (address) => address !== '0x0000000000000000000000000000000000000000',
  );
}

export function authVerifierConfigured(addresses = demoAddresses): boolean {
  return addresses.authVerifier !== '0x0000000000000000000000000000000000000000';
}
