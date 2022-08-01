<h1 align="center">
  blindnet devkit<br />
  .Net Core SDK
</h1>

<p align=center><img src="https://user-images.githubusercontent.com/7578400/163277439-edd00509-1d1b-4565-a0d3-49057ebeb92a.png#gh-light-mode-only" height="80" /></p>
<p align=center><img src="https://user-images.githubusercontent.com/7578400/163549893-117bbd70-b81a-47fd-8e1f-844911e48d68.png#gh-dark-mode-only" height="80" /></p>

<p align="center">
  <strong>.Net Core SDK for authentication tokens generation and user management</strong>
</p>

<p align="center">
  <a href="https://blindnet.dev"><strong>blindnet.dev</strong></a>
</p>

<p align="center">
  <a href="https://blindnet.dev/docs">Documentation</a>
  &nbsp;•&nbsp;
  <a href="https://github.com/blindnet-io/{project-short-name}/issues">Submit an Issue</a>
  &nbsp;•&nbsp;
  <a href="https://join.slack.com/t/blindnet/shared_invite/zt-1arqlhqt3-A8dPYXLbrnqz1ZKsz6ItOg">Online Chat</a>
  <br>
  <br>
</p>

## About

This is the .Net Core [server-side SDK](https://docs.blindnet.io/docs/glossary#server-side-sdk) component of [blindnet devkit][devkit] allowing you to:

- Generate [authentication tokens](https://docs.blindnet.io/docs/extra/glossary#authentication-token) to allow users to access blindnet.
- Manage application users and data on blindnet.

## Get Started

:rocket: Check out our [Quick Start Guide](https://blindnet.dev/docs/quickstart) to get started in a snap.

## Installation

<!-- FIXME: add install steps -->

Here you can find [NuGet package](https://www.nuget.org/packages/Blindnet.SDK.NetCore/).

Install with Package Manager:

```
Install-Package Blindnet.SDK.NetCore -Version 1.0.1
```

Install with .NET CLI:

```
dotnet add package Blindnet.SDK.NetCore --version 1.0.1
```

## Usage

### Initialization

You need to initialize blindnet SDK before you can use it.

```
var blindnet = Blindnet.Init(appKey, appId);
```

There is an optional param to define blindnet API endpoint that SDK will target, by defailt it's set to `https://api.blindnet.io`.

If you want to change endpoint:

```
var blindnet = Blindnet.Init(appKey, appId, apiEndpoint);
```

All SDK methods are availabe from Blindnet instance

```
var blindnet = Blindnet.Init(appKey, appId, apiEndpoint);
var token = blindnet.CreateUserToken(userId);
```

### Creating user tokens

Two types of tokens are needed: tokens for registered users and temporary tokens.

#### Create a token for a registered user

Creates a JWT for registered users of your application, usually data receivers.

```
public string CreateUserToken(string userId, string? groupId)
```

#### Create a temporary token

Creates a JWT for non-registered users of your application, usually data senders.

```
public string CreateTempUserToken(string? groupId)
```

### Deleting data keys

Deletes an encrypted data key from blindnet.

```
public async Task<bool> ForgetData(string dataId)
```

### Revoking access to user

Deletes all encrypted data keys of a given user.

```
public async Task<bool> RevokeAccess(string userId)
```

### Deleting user

Deletes a user from blindnet.

```
public async Task<bool> ForgetUser(string userId)
```

### Delete all users from group

Deletes all users that belong to the group and all their encrypted data keys.

```
public async Task<bool> ForgetGroup(string groupId)
```

## Contributing

Contributions of all kinds are always welcome!

If you see a bug or room for improvement in this project in particular, please [open an issue][new-issue] or directly [fork this repository][fork] to submit a Pull Request.

If you have any broader questions or suggestions, just open a simple informal [DevRel Request][request], and we'll make sure to quickly find the best solution for you.

## Community

> All community participation is subject to blindnet’s [Code of Conduct][coc].
> Stay up to date with new releases and projects, learn more about how to protect your privacy and that of our users, and share projects and feedback with our team.

- [Join our Slack Workspace][chat] to chat with the blindnet community and team
- Follow us on [Twitter][twitter] to stay up to date with the latest news
- Check out our [Openness Framework][openness] and [Product Management][product] on Github to see how we operate and give us feedback.

## License

The blindnet devkit sdk-dotnet-core-server is available under [MIT][license] (and [here](https://github.com/blindnet-io/openness-framework/blob/main/docs/decision-records/DR-0001-oss-license.md) is why).

<!-- project's URLs -->

[new-issue]: https://github.com/blindnet-io/sdk-dotnet-core-server/issues/new/choose
[fork]: https://github.com/blindnet-io/sdk-dotnet-core-server/fork

<!-- common URLs -->

[devkit]: https://github.com/blindnet-io/blindnet.dev
[openness]: https://github.com/blindnet-io/openness-framework
[product]: https://github.com/blindnet-io/product-management
[request]: https://github.com/blindnet-io/devrel-management/issues/new?assignees=noelmace&labels=request%2Ctriage&template=request.yml&title=%5BRequest%5D%3A+
[chat]: https://join.slack.com/t/blindnet/shared_invite/zt-1arqlhqt3-A8dPYXLbrnqz1ZKsz6ItOg
[twitter]: https://twitter.com/blindnet_io
[docs]: https://blindnet.dev/docs
[changelog]: CHANGELOG.md
[license]: LICENSE
[coc]: https://github.com/blindnet-io/openness-framework/blob/main/CODE_OF_CONDUCT.md
