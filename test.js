const w = window.open("https://login.microsoftonline.com/organizations/oauth2/v2.0/authorize?client_id=203f1145-856a-4232-83d4-a43568fba23d&scope=openid%20profile%20offline_access&redirect_uri=https%3A%2F%2Fcosmos.azure.com%2F&client-request-id=720acb57-7f01-4afc-b758-95519ee67590&response_mode=fragment&response_type=code&x-client-SKU=msal.js.browser&x-client-VER=2.14.2&x-client-OS=&x-client-CPU=&client_info=1&code_challenge=td7XZzYrKuKQR_yJjFWi2ZyV_h92W6lYrVQHUguPPWI&code_challenge_method=S256&nonce=49dce0f5-20fb-4999-836c-04c5dae78c3a&state=eyJpZCI6ImMzOGM0YWZjLTc2NzgtNGEwMi1hMTQ1LWQzZGEwNGQwYjI1NiIsIm1ldGEiOnsiaW50ZXJhY3Rpb25UeXBlIjoicG9wdXAifX0%3D", "");

setTimeout(() => {
  try {
    console.log(w.location.href);
  } catch (e) {
    console.warn("Can't access href:", e.message);
  }
}, 3000);
