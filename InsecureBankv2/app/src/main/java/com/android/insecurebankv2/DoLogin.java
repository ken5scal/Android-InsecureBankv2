package com.android.insecurebankv2;

import android.app.Activity;
import android.content.ContentValues;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.res.AssetManager;
import android.net.Uri;
import android.os.AsyncTask;
import android.os.Bundle;
import android.preference.PreferenceManager;
import android.util.Base64;
import android.util.Log;
import android.view.Menu;
import android.view.MenuItem;
import android.widget.Toast;

import org.apache.http.HttpResponse;
import org.apache.http.NameValuePair;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.HttpClient;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.message.BasicNameValuePair;
import org.json.JSONException;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.net.URL;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.AlgorithmParameterSpec;
import java.util.ArrayList;
import java.util.List;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

/*
The page that accepts new password and passes it on to the change password 
module. This new password can then be used by the user to log in to the account.
@author Dinesh Shetty
*/

public class DoLogin extends Activity {
    String responseString = null;
    //	Stores the username passed by the calling intent
    String username;
    //	Stores the password passed by the calling intent
    String password;
    String result;
    String superSecurePassword;
    String rememberme_username, rememberme_password;
    public static final String MYPREFS = "mySharedPreferences";
    String serverip = "";
    String serverport = "";
    String protocol = "http://";
    BufferedReader reader;
    SharedPreferences serverDetails;
    AssetManager assetManager;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_do_login);
        finish();

        // Get Server details from Shared Preference file.
        serverDetails = PreferenceManager.getDefaultSharedPreferences(this);
        serverip = serverDetails.getString("serverip", null);
        serverport = serverDetails.getString("serverport", null);
        assetManager = getResources().getAssets();
        if (serverip != null && serverport != null) {

            Intent data = getIntent();
            username = data.getStringExtra("passed_username");
            password = data.getStringExtra("passed_password");
            new RequestTask().execute("username");

        } else {
            Intent setupServerdetails = new Intent(this, FilePrefActivity.class);
            startActivity(setupServerdetails);
            Toast.makeText(this, "Server path/port not set!", Toast.LENGTH_LONG).show();

        }
    }

    class RequestTask extends AsyncTask<String, String, String> {

        @Override
        protected String doInBackground(String... params) {
            TrustManagerFactory trustManagerFactory;
            try {
                URL url = new URL("https://moneyforward.com");
                KeyStore ks = KeyStore.getInstance("BKS");
                ks.load(null);
                CertificateFactory factory = CertificateFactory.getInstance("X509");

                X509Certificate x509 = (X509Certificate) factory.generateCertificate(
                        assetManager.open("cacert.crt")
                );
                String alias = x509.getSubjectDN().getName();
                ks.setCertificateEntry(alias, x509);

                TrustManager tm = new X509TrustManager() {
                    @Override
                    public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {

                    }

                    @Override
                    public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {

                    }

                    @Override
                    public X509Certificate[] getAcceptedIssuers() {
                        return new X509Certificate[0];
                    }
                };

                trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
                trustManagerFactory.init(ks);

                SSLContext sslContext = SSLContext.getInstance("SSLv3");
                sslContext.init(null, new TrustManager[]{tm}, null);

                HttpsURLConnection.setDefaultSSLSocketFactory(sslContext.getSocketFactory());
                HttpsURLConnection.setDefaultHostnameVerifier(new HostnameVerifier() {
                    @Override
                    public boolean verify(String hostname, SSLSession session) {
                        return true;
                    }
                });

                HttpsURLConnection resp = (HttpsURLConnection) url.openConnection();
                resp.setSSLSocketFactory(sslContext.getSocketFactory());
                resp.getResponseCode();

                postData(params[0]);
            } catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException | InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException | IOException | JSONException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            } catch (KeyStoreException e) {
                e.printStackTrace();
            } catch (CertificateException e) {
                e.printStackTrace();
            } catch (KeyManagementException e) {
                e.printStackTrace();
            }

            return null;
        }

        protected void onPostExecute(Double result) {
        }

        protected void onProgressUpdate(Integer... progress) {
        }

        public void postData(String valueIWantToSend) throws ClientProtocolException, IOException, JSONException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {


            // Create a new HttpClient and Post Header

            HttpClient httpclient = new DefaultHttpClient();
            HttpPost httppost = new HttpPost(protocol + serverip + ":" + serverport + "/login");
            HttpPost httppost2 = new HttpPost(protocol + serverip + ":" + serverport + "/devlogin");

            // Add your data
            List<NameValuePair> nameValuePairs = new ArrayList<NameValuePair>(2);

            //                Delete below test accounts in production
            //                nameValuePairs.add(new BasicNameValuePair("username", "jack"));
            //                nameValuePairs.add(new BasicNameValuePair("password", "jack@123$"));

            nameValuePairs.add(new BasicNameValuePair("username", username));
            nameValuePairs.add(new BasicNameValuePair("password", password));
            HttpResponse responseBody;
            if (username.equals("devadmin")) {
                httppost2.setEntity(new UrlEncodedFormEntity(nameValuePairs));
                // Execute HTTP Post Request
                responseBody = httpclient.execute(httppost2);
            } else {
                httppost.setEntity(new UrlEncodedFormEntity(nameValuePairs));
                // Execute HTTP Post Request
                responseBody = httpclient.execute(httppost);
            }

            InputStream in = responseBody.getEntity().getContent();
            result = convertStreamToString(in);
            result = result.replace("\n", "");
            if (result != null) {
                if (result.indexOf("Correct Credentials") != -1) {

                    Log.v("Unfavorable Log:", ", Some Sensitive Information goes here");


                    saveCreds(username, password);
                    trackUserLogins();
                    Intent pL = new Intent(getApplicationContext(), PostLogin.class);
                    pL.putExtra("uname", username);
                    startActivity(pL);
                } else {
                    Intent xi = new Intent(getApplicationContext(), WrongLogin.class);
                    startActivity(xi);
                }
            }
        }

        /*
        The function that tracks all the users who have successfully
        logged in to the application using that device
        */
        private void trackUserLogins() {
            // TODO Auto-generated method stub
            runOnUiThread(new Runnable() {

                @Override
                public void run() {
                    // TODO Auto-generated method stub
                    ContentValues values = new ContentValues();
                    values.put(TrackUserContentProvider.name, username);
                    // Inserts content into the Content Provider to track the logged in user's list
                    Uri uri = getContentResolver().insert(TrackUserContentProvider.CONTENT_URI, values);

                }
            });

        }

        /*
        The function that saves the credentials locally for future reference
        username: username entered by the user
        password: password entered by the user
        */
        private void saveCreds(String username, String password) throws UnsupportedEncodingException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
            // TODO Auto-generated method stub
            SharedPreferences mySharedPreferences;
            mySharedPreferences = getSharedPreferences(MYPREFS, Activity.MODE_PRIVATE);
            SharedPreferences.Editor editor = mySharedPreferences.edit();
            rememberme_username = username;
            rememberme_password = password;

            String key = "hogehoge";
            byte[] keyBytes = key.getBytes("UTF-8");
            byte[] ivBytes = {
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
            };
            AlgorithmParameterSpec ivSpec = new IvParameterSpec(ivBytes);
            SecretKeySpec newKey = new SecretKeySpec(keyBytes, "DES");
            Cipher cipher = null;
            cipher = Cipher.getInstance("DES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, newKey, ivSpec);
            byte[] encrypted = cipher.doFinal(rememberme_password.getBytes("UTF-8"));

            String base64Username = Base64.encodeToString(encrypted, Base64.DEFAULT);
            CryptoClass crypt = new CryptoClass();
            superSecurePassword = crypt.aesEncryptedString(rememberme_password);
            editor.putString("EncryptedUsername", base64Username);
            editor.putString("superSecurePassword", superSecurePassword);
            editor.commit();
        }

        private String convertStreamToString(InputStream in) throws IOException {
            // TODO Auto-generated method stub
            try {
                reader = new BufferedReader(new InputStreamReader(in, "UTF-8"));
            } catch (UnsupportedEncodingException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            }
            StringBuilder sb = new StringBuilder();
            String line = null;
            while ((line = reader.readLine()) != null) {
                sb.append(line + "\n");
            }
            in.close();
            return sb.toString();
        }
    }

    // Added for handling menu operations
    @Override
    public boolean onCreateOptionsMenu(Menu menu) {

        // Inflate the menu; this adds items to the action bar if it is present.
        getMenuInflater().inflate(R.menu.main, menu);
        return true;
    }

    // Added for handling menu operations
    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        int id = item.getItemId();
        if (id == R.id.action_settings) {
            callPreferences();
            return true;
        } else if (id == R.id.action_exit) {
            Intent i = new Intent(getBaseContext(), LoginActivity.class);
            i.addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP);
            startActivity(i);
            return true;
        }
        return super.onOptionsItemSelected(item);
    }

    public void callPreferences() {
        // TODO Auto-generated method stub
        Intent i = new Intent(this, FilePrefActivity.class);
        startActivity(i);
    }

}