
export function getUserAddress(srID) {
  const usrData = JSON.parse(localStorage.getItem(srID));
  return usrData.address;
}
