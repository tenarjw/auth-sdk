
import { loginWebAuthnTest, registerWebAuthnTest } from './test_WebAuthn'; 

function App() {


  return (
    <div className="App">

<button onClick={() => registerWebAuthnTest().catch(console.error)}>
  1. Zarejestruj klucz (symulator lub sprzętowy)
</button>

<button onClick={() => loginWebAuthnTest().catch(console.error)}>
  2. Zaloguj się (po rejestracji)
</button>
    </div>
  );
}

export default App;
