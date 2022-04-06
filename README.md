<div id="top"></div>

[![Contributors][contributors-shield]][contributors-url]
[![Forks][forks-shield]][forks-url]
[![Stargazers][stars-shield]][stars-url]
[![Issues][issues-shield]][issues-url]
[![Apache License][license-shield]][license-url]
[![LinkedIn][linkedin-shield]][linkedin-url]

<h3 align="center">PCAP Utilities</h3>

  <p align="center">
    This project is a collection of utilities to generate, download, and work with BIG-IP packet captures.
    <br />
    <a href="https://github.com/f5-rahm/pcap_utils/issues">Report Bug</a>
    ·
    <a href="https://github.com/f5-rahm/pcap_utils/issues">Request Feature</a>
  </p>

<!-- TABLE OF CONTENTS -->
<details>
  <summary>Table of Contents</summary>
  <ol>
    <li>
      <a href="#about-the-project">About The Project</a>
      <ul>
        <li><a href="#built-with">Built With</a></li>
      </ul>
    </li>
    <li>
      <a href="#getting-started">Getting Started</a>
      <ul>
        <li><a href="#installation">Installation</a></li>
      </ul>
    </li>
    <li><a href="#usage">Usage</a></li>
    <li><a href="#roadmap">Roadmap</a></li>
    <li><a href="#contributing">Contributing</a></li>
    <li><a href="#license">License</a></li>
    <li><a href="#contact">Contact</a></li>
    <li><a href="#acknowledgments">Acknowledgments</a></li>
  </ol>
</details>

### Built With

* [Python](https://www.python.org/)
* [BIGREST](https://bigrest.readthedocs.io/)

<p align="right">(<a href="#top">back to top</a>)</p>


<!-- GETTING STARTED -->
## Getting Started

This is an example of how you may give instructions on setting up your project locally.
To get a local copy up and running follow these simple example steps.


### Installation

1. Clone the repo
   ```sh
   git clone https://github.com/f5-rahm/pcap_utils.git
   ```
2. Create and activate a virtual environment
   ```sh
   # linux/macos
   python3 -m venv /path/to/new/virtual/environment
   source <venv>/bin/activate
   # windows
   c:\>c:\Python39\python -m venv c:\path\to\myenv
   # cmd.exe
   C:\> <venv>\Scripts\activate.bat
   # powershell
   PS C:\> <venv>\Scripts\Activate.ps1
   ```
3. Install requirements
   ```sh
   pip install -r requirements.txt
   ```

<p align="right">(<a href="#top">back to top</a>)</p>


<!-- USAGE EXAMPLES -->
## Usage

The first utility in this project, [support_captures.py](support_captures.py), takes no arguments, but does require three environment variables:

- F5_HOST
- F5_USER
- F5_PASS

Once starting the script, it will ask you for three things:

- The virtual server under test
- The client IP you will be testing from (and that is observable inbound on BIG-IP)
- The F5 support case number you'll upload files to

Once the tcpdump capture is started for you, you'll have about 50 seconds to reproduce your issue. 
This might be extensible but YMMV. Here's a sample run through the script with the ssl profile cache set to zero.

```sh
python support_captures.py


	#################################################
	### BIG-IP tcpdump capture collection utility ###
	#################################################

	Virtual name: ext_nerdknobs.tech_443
	Client IP for test traffic: 174.209.224.94
	Case number: C245197
	
	-------------------------------------------------

	Virtual ext_nerdknobs.tech_443 has associated client-ssl profile cssl_nerdknobs.tech...continuing.
	Session keylogger iRule (cache disabled version) created...continuing.
	Session keylogger iRule applied to ext_nerdknobs.tech_443...continuing.
	Starting tcpdump...please reproduce your issue now.
	Session keylogger iRule removed from ext_nerdknobs.tech_443...continuing.
	keylogger iRule deleted...continuing.
	Secrets key file created (with cache disabled command)...continuing.
	Starting qkview...standby.
	Qkview still running...sleeping 10 seconds.
	Qkview complete...continuing.
	Downloading support files from BIG-IP.
		C245197_2022-04-06.pcap downloaded.
		C245197_sessionsecrets.pms downloaded.
		C245197_ltm3.test.local.qkview downloaded.
	All support files downloaded...continuing.
	Cleaning up support files on BIG-IP.
		C245197_2022-04-06.pcap deleted.
		C245197_sessionsecrets.pms deleted.
		C245197_ltm3.test.local.qkview deleted.
	All support files cleaned up on BIG-IP...complete.
	
-------------------------------------------------

Please upload files in output_files directory to your support case or to supportfiles.f5.com using credentials provided by your case worker.
```

<p align="right">(<a href="#top">back to top</a>)</p>


<!-- ROADMAP -->
## Roadmap

- [ ] Utility to decrypt downloaded BIG-IP captures
- [ ] Utility to match and visualize clientside/serverside BIG-IP flows using f5ethtrailer details
- [ ] Utility to isolate SIP/RTP flows
- [ ] APM flow clarity, issue isolation

See the [open issues](https://github.com/f5-rahm/pcap_utils/issues) for a full list of proposed features (and known issues).

<p align="right">(<a href="#top">back to top</a>)</p>



<!-- CONTRIBUTING -->
## Contributing

Contributions are what make the open source community such an amazing place to learn, inspire, and create. Any contributions you make are **greatly appreciated**.

If you have a suggestion that would make this better, please fork the repo and create a pull request. You can also simply open an issue with the tag "enhancement".
Don't forget to give the project a star! Thanks again!

1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3. Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the Branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

<p align="right">(<a href="#top">back to top</a>)</p>



<!-- LICENSE -->
## License

Distributed under the Apache 2.0 License. See `LICENSE` for more information.

<p align="right">(<a href="#top">back to top</a>)</p>



<!-- CONTACT -->
## Contact

Your Name - [@jasonrahm](https://twitter.com/jasonrahm) - j.rahm@f5.com

Project Link: [https://github.com/f5-rahm/pcap_utils](https://github.com/f5-rahm/pcap_utils)

<p align="right">(<a href="#top">back to top</a>)</p>



<!-- ACKNOWLEDGMENTS -->
## Acknowledgments

* Jay Smellow
* Delane Jackson
* The Python Community
* [Othneil Drew](https://github.com/othneildrew/Best-README-Template) for this readme template!

<p align="right">(<a href="#top">back to top</a>)</p>



<!-- MARKDOWN LINKS & IMAGES -->
<!-- https://www.markdownguide.org/basic-syntax/#reference-style-links -->
[contributors-shield]: https://img.shields.io/github/contributors/f5-rahm/pcap_utils.svg?style=for-the-badge
[contributors-url]: https://github.com/f5-rahm/pcap_utils/graphs/contributors
[forks-shield]: https://img.shields.io/github/forks/f5-rahm/pcap_utils.svg?style=for-the-badge
[forks-url]: https://github.com/f5-rahm/pcap_utils/network/members
[stars-shield]: https://img.shields.io/github/stars/f5-rahm/pcap_utils.svg?style=for-the-badge
[stars-url]: https://github.com/f5-rahm/pcap_utils/stargazers
[issues-shield]: https://img.shields.io/github/issues/f5-rahm/pcap_utils.svg?style=for-the-badge
[issues-url]: https://github.com/f5-rahm/pcap_utils/issues
[license-shield]: https://img.shields.io/github/license/f5-rahm/pcap_utils.svg?style=for-the-badge
[license-url]: https://github.com/f5-rahm/pcap_utils/blob/master/LICENSE
[linkedin-shield]: https://img.shields.io/badge/-LinkedIn-black.svg?style=for-the-badge&logo=linkedin&colorB=555
[linkedin-url]: https://linkedin.com/in/jrahm