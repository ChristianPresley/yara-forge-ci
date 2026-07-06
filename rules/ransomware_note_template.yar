/*
    Detection idea: Ransom-note text artifacts (README/DECRYPT files). Whether
    hand-written or LLM-generated, ransom notes share a stable rhetorical skeleton:
    "your files have been encrypted", a payment/negotiation channel (Tor .onion or
    a contact email), and a decryption/deadline threat. Detecting the note is a
    reliable, sample-free signal of a completed encryption stage.

    Performance notes:
    - Phrase atoms are long and specific; the .onion regex is bounded to the
      exact v3 length (56 base32 chars) to stay linear.
    - Requires an encryption claim AND a contact/payment channel to fire, which
      keeps benign security writing about ransomware from matching.
*/

rule Ransomware_Note_Template
{
    meta:
        author        = "Christian Presley"
        date          = "2026-05-14"
        description   = "Detects ransom-note artifacts (encryption claim + payment/contact channel + threat)"
        reference     = "https://attack.mitre.org/techniques/T1486/"
        mitre_attack  = "T1486"
        severity      = "high"
        version       = "1.0"

    strings:
        // Encryption claims
        $enc1 = "your files have been encrypted" nocase ascii wide
        $enc2 = "all your files are encrypted" nocase ascii wide
        $enc3 = "your network has been encrypted" nocase ascii wide
        $enc4 = "your documents, photos, databases" nocase ascii wide

        // Payment / contact channels
        $chan1 = ".onion" nocase ascii wide
        $chan2 = /[a-z2-7]{56}\.onion/ nocase ascii          // Tor v3 address shape
        $chan3 = "bitcoin" nocase ascii wide
        $chan4 = "BTC wallet" nocase ascii wide
        $chan5 = "contact us at" nocase ascii wide
        $chan6 = "to decrypt your files" nocase ascii wide

        // Threat / deadline
        $thr1 = "will be permanently deleted" nocase ascii wide
        $thr2 = "price will be doubled" nocase ascii wide
        $thr3 = "do not rename" nocase ascii wide
        $thr4 = "decryption key" nocase ascii wide

    condition:
        1 of ($enc*)
        and 1 of ($chan*)
        and 1 of ($thr*)
}
