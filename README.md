# crt_sh

[![Go Report Card](https://goreportcard.com/badge/github.com/wh0ami7/crt_sh)](https://goreportcard.com/report/github.com/wh0ami7/crt_sh)
[![Build Status](https://github.com/wh0ami7/crt_sh/actions/workflows/release.yml/badge.svg)](https://github.com/wh0ami7/crt_sh/actions/workflows/go.yml)
[![Release](https://img.shields.io/github/v/release/wh0ami7/crt_sh)](https://github.com/wh0ami7/crt_sh/releases)
[![License](https://img.shields.io/github/license/wh0ami7/crt_sh)](https://github.com/wh0ami7/crt_sh/blob/main/LICENSE)
[![Contributors](https://img.shields.io/github/contributors/wh0ami7/crt_sh)](https://github.com/wh0ami7/crt_sh/graphs/contributors)
[![Commit Activity](https://img.shields.io/github/commit-activity/m/wh0ami7/crt_sh)](https://github.com/wh0ami7/crt_sh/graphs/commit-activity)
[![Last Commit](https://img.shields.io/github/last-commit/wh0ami7/crt_sh)](https://github.com/wh0ami7/crt_sh/commits/main)
[![Code Size](https://img.shields.io/github/languages/code-size/wh0ami7/crt_sh)](https://github.com/wh0ami7/crt_sh)
[![Issues](https://img.shields.io/github/issues/wh0ami7/crt_sh)](https://github.com/wh0ami7/crt_sh/issues)
[![Pull Requests](https://img.shields.io/github/issues-pr/wh0ami7/crt_sh)](https://github.com/wh0ami7/crt_sh/pulls)
[![Forks](https://img.shields.io/github/forks/wh0ami7/crt_sh)](https://github.com/wh0ami7/crt_sh/network/members)
[![Stars](https://img.shields.io/github/stars/wh0ami7/crt_sh)](https://github.com/wh0ami7/crt_sh/stargazers)

A Simple Golang tool to fetch root domains from crt.sh.

## Features

* Fetches root domains related to a given domain from crt.sh.
* Useful for discovering subdomains and related domains for security assessments, penetration testing, or reconnaissance.
* Provides a quick and easy way to gather information about a domain's certificate history.

## Usage

1.  **Clone the repository:**

    ```bash
    git clone [https://github.com/wh0ami7/crt_sh.git](https://github.com/wh0ami7/crt_sh.git)
    ```

2.  **Navigate to the project directory:**

    ```bash
    cd crt_sh
    ```

3.  **Build the tool:**

    ```bash
    go build -v -o crt_sh .
    ```

4.  **Run the tool with a domain:**

    ```bash
    ./crt_sh example.com
    ```

    This will fetch root domains related to `example.com` from crt.sh.

**Example:**

To fetch root domains for `google.com` in quiet mode, you would run:

```bash
./crt_sh -q google.com
