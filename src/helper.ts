export function defineURL(url: string) {
  const regex = /^(?:http(s)?:\/\/)?[\w.-]+(?:\.[\w\.-]+)+[\w\-\._~:\/?#[\]@!\$&'\(\)\*\+,;=.]+$/gm;
  if (regex.exec(url)) {
    return true;
  }
  return false;
}
