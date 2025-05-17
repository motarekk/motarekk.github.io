<h1 align="center">playascon</h1>
<p align="center">
<img width="250" alt="ascon_sponge_canal_system" src="https://github.com/motarekk/motarekk.github.io/assets/104282801/206bd7c5-f184-4f53-9ccb-eba4c5221787">
</p>

### First online tool for <a href="https://ascon.iaik.tugraz.at/" target="_blank">Ascon cipher</a> on the internet [<a href="https://medium.com/@motarekk/playascon-3aba1fbad330" target="_blank">blogpost</a>]
<p><a href="https://motarekk.github.io/" target="_blank">playascon</a> is a Javascript implementation of Ascon cipher that runs in your browser without any server-side latency. There is no ads or fancy designs, and it's obviously open source.</p>

### UPDATE
The code has been updated to meet the NIST SP 800-232 standard.

### Supported variants
<li>Ascon-AEAD128</li>
<li>Ascon-Hash256</li>
<li>Ascon-XOF128</li>
<li>Ascon-CXOF128</li>

### Features
<p>Along with the basic functionality of the tool which is encryption, decryption, and hashing, there are two other features to mention:</p>
<li>Support for Non-English texts</li>
<li>Input format can be raw text or hexadecimal data</li>

### Known Answer Tests (KATs)
<p>To ensure the correctness of playascon results, I used Known Answer Tests (KATs) generated from the <a href="https://github.com/meichlseder/pyascon" target="_blank">Python implementation of Ascon</a>by <a href="https://www.iaik.tugraz.at/person/maria-eichlseder/" target="_blank">Maria Eichlseder</a> (one of the Ascon authors). You can also run the tests yourself from the <a href="https://motarekk.github.io/KATs/KAT.html" target="_blank">KATs page.</a></p>
<p>(To have an idea what these KATs look like, you can visit: https://motarekk.github.io/KATs/LWC_AEAD_KAT_128.js)</p>

### Capture The Flag (CTF)
<p>To make this tool more fun, I’ve added an easy CTF (Capture The Flag) challenge to be solved. I am planning to add more challenges, to help you visualize how a nonce misuse attack could take place for example.</p>

<img width="810" alt="playascon_ctf" src="https://github.com/user-attachments/assets/bd5f0c8b-53e4-4a6a-85a6-fb4ac566b63a" />

### Hall of Fame (HoF)
<p>After the <a href="https://groups.google.com/a/list.nist.gov/g/lwc-forum/c/1k6o4hlYG6A" target="_blank">initial release</a> of playascon, people started testing it and found some bugs in the format of the data displayed. You can find the two issues here:</p>
<li>By Joshua Holden: https://github.com/motarekk/motarekk.github.io/issues/1</li>
<li>By Majid M.Niknam: https://groups.google.com/a/list.nist.gov/g/lwc-forum/c/1k6o4hlYG6A/m/gaYrfxFxAgAJ</li>
As a sign of appreciation for reaching out, I made a Hall of Fame to list their names. And that’s the beauty of open source projects, when people reach out to fix bugs and get acknowledged, and other users get the benefit of a well-functional project.

### Feedback
<p>I hope playascon will be the way-to-go tool for students to play out with Ascon, which is expected to have a very important role in the upcoming era of securing lightweight devices. The main reward I am welling to get from this project is to see feedbacks like this:</p>

<img width="452" alt="github_comment" src="https://github.com/motarekk/motarekk.github.io/assets/104282801/2950b84f-545c-4047-9cca-0d9e2dff2028">
<p>Also, if you have any suggestions to modify or add something to the tool, feel free to raise an issue or email me at 0xmohamed.tarek@gmail.com</p>
