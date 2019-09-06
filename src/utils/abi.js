export const ATTESTATION_ABI = [
    'event Attest(address _address,string _type,string _data)',
    'function write(string _type,string _data) public returns (bool)'
];

export const VANITYURL_ABI = [
    'event VanityReserved(address _to, string _vanity_url)',
    'function reserve(string _vanity_url,string _springrole_id)',
    'function changeVanityURL(string _vanity_url, string _springrole_id)'
];

export const ERC20 = ['function balanceOf(address owner)'];
