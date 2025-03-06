# crt_sh

[![Go Report Card](https://goreportcard.com/badge/github.com/wh0ami7/crt_sh)](https://goreportcard.com/report/github.com/wh0ami7/crt_sh)
[![Build Status](https://github.com/wh0ami7/crt_sh/actions/workflows/go.yml/badge.svg)](https://github.com/wh0ami7/crt_sh/actions/workflows/go.yml)
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
![GitHub Downloads (all assets, all releases)](https://img.shields.io/github/downloads/wh0ami7/crt_sh/total)


A Simple Golang tool to fetch root domains from crt.sh.

## Features

`crt_sh` is a command-line tool that queries certificate transparency logs to retrieve DNS certificates for a specified domain. It efficiently extracts root domain names and stores them in a local BoltDB database for offline access.

## Usage

1. Basic Query
Retrieve certificates for example.com:

```bash
    crt_sh -d example.com
```

2. Verbose Mode
Query example.com with detailed output:

```bash
    crt_sh -d example.com -v
```
3. Retrive domains from previously completed scans:

```bash
    crt_sh -d example.com -c
```