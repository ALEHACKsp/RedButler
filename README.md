[![Contributors][contributors-shield]][contributors-url]
[![Forks][forks-shield]][forks-url]
[![Stargazers][stars-shield]][stars-url]
[![Issues][issues-shield]][issues-url]

<p align="center">
  <a href="https://github.com/Zeta314/RedButler">
    <img src="images/logo.png" alt="Logo" width="80" height="80">
  </a>

  <h3 align="center">RedButler</h3>

  <p align="center">
    RedButler is a windows kernel driver that lets you acquire the super powers of ring 0
    just by loading it and using its CLI!
    <br />
    <br />
    <a href="https://github.com/github_username/repo_name/issues">Report Bug</a>
    ·
    <a href="https://github.com/github_username/repo_name/issues">Request Feature</a>
  </p>
</p>

<!-- ABOUT THE PROJECT -->
## About The Project

RedButler is a windows kernel driver that, by loading it, lets you acquire ring 0 superpowers!
It offers various features among:
 * Hiding / showing files and directories
 * Protecting processes 
 * Excluding processes from protection
 * Injecting DLL into processes (PPL ones excluded)

<!-- GETTING STARTED -->
## Getting Started

Just download the latest compiled release of the driver and install it using the `RedButler.ini` file.

If you prefer compiling it by yourself, feel free to do it.
You'll just need the Windows Driver Kit (windows 10).

<!-- USAGE EXAMPLES -->
## Usage

Process protection
```
RedCLI.exe process --protect <PID>
RedCLI.exe process --unprotect <PID>
```

Process exclusion
```
RedCLI.exe process --exclude <PID>
RedCLI.exe process --unexclude <PID>
```

Filesystem manipulation
```
RedCLI.exe filesystem --hide --file <path>
RedCLI.exe filesystem --hide --directory <path>

RedCLI.exe filesystem --unhide --file <rule id>
RedCLI.exe filesystem --unhide --directory <rule id>
```


<!-- CONTRIBUTING -->
## Contributing

Contributions are what make the open source community such an amazing place to be learn, inspire, and create. Any contributions you make are **greatly appreciated**.

1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3. Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the Branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request



<!-- LICENSE -->
## License

Distributed under the MIT License. See `LICENSE` for more information.


<!-- MARKDOWN LINKS & IMAGES -->
<!-- https://www.markdownguide.org/basic-syntax/#reference-style-links -->
[contributors-shield]: https://img.shields.io/github/contributors/Zeta314/RedButler.svg
[contributors-url]: https://github.com/Zeta314/RedButler/graphs/contributors
[forks-shield]: https://img.shields.io/github/forks/Zeta314/RedButler.svg
[forks-url]: https://github.com/Zeta314/RedButler/network/members
[stars-shield]: https://img.shields.io/github/stars/Zeta314/RedButler.svg
[stars-url]: https://github.com/Zeta314/RedButler/stargazers
[issues-shield]: https://img.shields.io/github/issues/Zeta314/RedButler.svg
[issues-url]: https://github.com/Zeta314/RedButler/issues
