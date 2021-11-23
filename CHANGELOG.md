# Changelog
All notable changes to this project will be documented in this file.
This application follows the [Semantic Versioning standard](https://semver.org/).

## Unreleased
- 

## Version 0.3.0 (2021-11-15)
- Removed all unsafe code. (#9)
- Change in policy, there is no need for unsafe code in the future. (#9)
- `qrcode::EcLevel` implements `From<ErrorCorrectionLevel>` instead for
`ErrorCorrectionLevel` implementing `Into<qrcode::EcLevel>`
(only when "with-qrcode" feature is enabled). (#9)

## Pre version 0.3.0 (2020-10-12)
All changes before 2020-10-12 where not documented.
This is everything before and including: 388f6933301df132aaf94982b7f15c9dce3f2e06