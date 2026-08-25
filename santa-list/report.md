---
title: Santa List Audit Report
author: Neo_Ryujin
date: Aug 24, 2026
# header-includes:
#   - \usepackage{titling}
#   - \usepackage{graphicx}
---

<!-- \begin{titlepage}
    \centering
    \begin{figure}[h]
        \centering
        \includegraphics[width=0.5\textwidth]{logo.pdf} 
    \end{figure}
    \vspace*{2cm}
    {\Huge\bfseries TSwap Protocol Audit Report\par}
    \vspace{1cm}
    {\Large Version 1.0\par}
    \vspace{2cm}
    {\Large\itshape Cyfrin.io\par}
    \vfill
    {\large \today\par}
\end{titlepage}

\maketitle -->

<!-- Your report starts here! -->

Prepared by: [Ryujin](https://github.com/Neo-Ryujin-Core)

Lead Auditors: 
- Ryujin

# Table of Contents
- [Table of Contents](#table-of-contents)
- [Risk Classification](#risk-classification)
- [Executive Summary](#executive-summary)
  - [Issues found](#issues-found)
- [Findings](#findings)
  - [High](#high)
    - [\[H-1\] Missing Access Control in `SantaList::checkList` Allows Anyone to Set Their Status to `EXTRA_NICE` and Collect Exclusive Rewards](#h-1-missing-access-control-in-santalistchecklist-allows-anyone-to-set-their-status-to-extra_nice-and-collect-exclusive-rewards)
    - [\[H-2\] `SantaList::buyPresent` Allows Attackers to Burn Users' SantaTokens While Receiving the NFT](#h-2-santalistbuypresent-allows-attackers-to-burn-users-santatokens-while-receiving-the-nft)
    - [\[H-3\] The `SantaList::s_theListCheckedOnce` and `SantaList::s_theListCheckedTwice` store the same `Status` value, allowing users to collect presents after only one check](#h-3-the-santalists_thelistcheckedonce-and-santalists_thelistcheckedtwice-store-the-same-status-value-allowing-users-to-collect-presents-after-only-one-check)
  - [Informational](#informational)
    - [\[I-1\] Unused `Status::NOT_CHECKED_TWICE` Enum Value and `PURCHASED_PRESENT_COST` Constant](#i-1-unused-statusnot_checked_twice-enum-value-and-purchased_present_cost-constant)


# Risk Classification

|            |        | Impact |        |     |
| ---------- | ------ | ------ | ------ | --- |
|            |        | High   | Medium | Low |
|            | High   | H      | H/M    | M   |
| Likelihood | Medium | H/M    | M      | M/L |
|            | Low    | M      | M/L    | L   |

I use the [CodeHawks](https://docs.codehawks.com/hawks-auditors/how-to-evaluate-a-finding-severity) severity matrix to determine severity. See the documentation for more details.

# Executive Summary
## Issues found

| Severtity | Number of issues found |
| --------- | ---------------------- |
| High      | 3                      |
| Medium    | 0                      |
| Low       | 0                      |
| Info      | 1                      |
| Total     | 4                      |


# Findings
## High

### [H-1] Missing Access Control in `SantaList::checkList` Allows Anyone to Set Their Status to `EXTRA_NICE` and Collect Exclusive Rewards

**Description:** The NatSpec documentation for `SantaList::checkList` states that the function is only callable by Santa. However, the function does not use the `SantaList::onlySanta` modifier.

As a result, any user can call `SantaList::checkList` and arbitrarily set their own status, or another user's status, to `Status.EXTRA_NICE`. This allows users who were originally classified as `NICE` or `NAUGHTY` to change their status to `EXTRA_NICE` and become eligible to collect presents intended exclusively for `EXTRA_NICE` users.

```javascript
    /* 
     * @notice Do a first pass on someone if they are naughty or nice. 
     * Only callable by santa
     * 
     * @param person The person to check
     * @param status The status of the person
     */
    
@>  function checkList(address person, Status status) external {
        s_theListCheckedOnce[person] = status;
        emit CheckedOnce(person, status);
    }
```

**Impact:** An attacker can bypass the intended access-control mechanism and assign themselves the `EXTRA_NICE` status. They can then collect presents that are intended exclusively for users who were legitimately classified as `EXTRA_NICE`.

This can result in unauthorized distribution of both SantaTokens and NFTs, depending on the protocol's reward flow.

**Proof of Concept:**

Paste below code in `SantaListTest.t.sol` file and run test command 

```javascript
    function test_anyoneCanCallCheckList() public {
        vm.prank(user);
        santasList.checkList(user, SantasList.Status.EXTRA_NICE);
        assertEq(uint256(santasList.getNaughtyOrNiceOnce(user)), uint256(SantasList.Status.EXTRA_NICE));
    }
```    

**Recommended Mitigation:** 

Add the modifier in function `SantaList::checkList` 

```diff
-   function checkList(address person, Status status) external {
+   function checkList(address person, Status status) external onlySanta {    
```


### [H-2] `SantaList::buyPresent` Allows Attackers to Burn Users' SantaTokens While Receiving the NFT

**Description:** `SantaList::buyPresent` accepts an arbitrary `presentReceiver` address and uses this address as the account from which `1e18` SantaTokens are burned:

```javascript
    function buyPresent(address presentReceiver) external {
@>        i_santaToken.burn(presentReceiver);
          _mintAndIncrement();
    }
```
The `SantaToken::burn` function only verifies that the caller is the authorized SantaList contract:

```javascript
    function burn(address from) external {
        if (msg.sender != i_santasList) {
            revert SantaToken__NotSantasList();
        }

@>      _burn(from, 1e18);
    }
```
There is no validation that `presentReceiver` is the same address as `msg.sender`.
Consequently, an attacker can call: `buyPresent(victim)`;
The SantaList contract will burn `1e18` SantaTokens from the victim, while `_mintAndIncrement()` mints the NFT to `msg.sender`, which is the attacker.
This is possible because `collectPresent()` gives each eligible address `1e18` SantaTokens, but `buyPresent()` does not require the caller to be the owner of the tokens being burned.

**Impact:** An attacker can spend another user's SantaTokens without their authorization and receive the corresponding NFT for themselves.
An attacker can do this against other eligible addresses, potentially draining the SantaTokens distributed to them.

**Proof of Concept:**

Add the following test to `SantaListTest.t.sol` and run test command.

```javascript
    function test_anyoneCanBuyPresentEvenWhenNotHavingSantaToken() public {

        address attacker = makeAddr("attacker");

        vm.startPrank(santa);
        santasList.checkList(user, SantasList.Status.EXTRA_NICE);
        santasList.checkTwice(user, SantasList.Status.EXTRA_NICE);
        vm.stopPrank();

        vm.warp(santasList.CHRISTMAS_2023_BLOCK_TIME() + 1);

        vm.startPrank(user);
        santasList.collectPresent();
        vm.stopPrank();

        vm.startPrank(attacker);
        console2.log("Attacker's santa token balance before buying present", santaToken.balanceOf(attacker));
        console2.log("User's santa token balance before buying present", santaToken.balanceOf(user));
        santasList.buyPresent(user);
        assertEq(santasList.balanceOf(attacker), 1);
        assertEq(santaToken.balanceOf(user), 0);
        vm.stopPrank();

    }

```

**Recommended Mitigation:** The intended behavior is that users can only purchase a present using their own SantaTokens, remove the user-controlled `presentReceiver` parameter and burn tokens from `msg.sender`:

```diff
- function buyPresent(address presentReceiver) external {
-     i_santaToken.burn(presentReceiver);
+ function buyPresent() external {
+     i_santaToken.burn(msg.sender);
      _mintAndIncrement();
}
```

### [H-3] The `SantaList::s_theListCheckedOnce` and `SantaList::s_theListCheckedTwice` store the same `Status` value, allowing users to collect presents after only one check

**Description:** The `SantaList::s_theListCheckedOnce` and `SantaList::s_theListCheckedTwice` mappings both store a `Status` value for the same user address:

```javascript
    mapping(address person => Status naughtyOrNice) private s_theListCheckedOnce;
    mapping(address person => Status naughtyOrNice) private s_theListCheckedTwice;
```

The `SantaList::collectPresent()` function determines whether a user has been checked twice by comparing the values stored in both mappings. However, `s_theListCheckedTwice` is only updated when `checkTwice()` is called, and its default value is the first enum value, `Status.NICE`.

Therefore, if a user is checked only once and receives `Status.NICE`, both of the following conditions evaluate to true even though `checkTwice()` was never called:

```javascript
    s_theListCheckedOnce[msg.sender] == Status.NICE s_theListCheckedTwice[msg.sender] == Status.NICE
```

As a result, the contract incorrectly considers the user to have passed Santa's second check.

**Impact:** An attacker can collect a present without being checked twice by Santa. This bypasses the intended two-step verification process and allows users who have only been checked once with `Status.NICE` to receive the present.

**Proof of Concept:** 

Paste below code in `SantaListTest.t.sol` file and run test command 

```javascript
    function test_onlyOnceEnteredWorking() public{
        vm.startPrank(user);
        santasList.checkList(user, SantasList.Status.NICE);
        vm.warp(santasList.CHRISTMAS_2023_BLOCK_TIME() + 1);
        santasList.collectPresent();
        vm.stopPrank();

        assertEq(santasList.balanceOf(user), 1);
    }
``` 

The test passes even though `checkTwice()` was never called for user.

**Recommended Mitigation:** 

Use a `bool` mapping to explicitly track whether a user has completed the second check. This separates the user's status from the verification state and prevents the default enum value from being interpreted as a successful second check.

```diff
    mapping(address person => Status naughtyOrNice) private s_theListCheckedOnce;
-   mapping(address person => Status naughtyOrNice) private s_theListCheckedTwice;
+   mapping(address person => bool) private s_theListCheckedTwice;

    function checkTwice(address person, Status status) external onlySanta {
        if (s_theListCheckedOnce[person] != status) {
            revert SantasList__SecondCheckDoesntMatchFirst();
        }
-       s_theListCheckedTwice[person] = status;
+       s_theListCheckedTwice[person] = true;
        emit CheckedTwice(person, status);
    }

    function collectPresent() external {
        if (block.timestamp < CHRISTMAS_2023_BLOCK_TIME) {
            revert SantasList__NotChristmasYet();
        }
        if (balanceOf(msg.sender) > 0) {
            revert SantasList__AlreadyCollected();
        }
-       if (s_theListCheckedOnce[msg.sender] == Status.NICE && s_theListCheckedTwice[msg.sender] == Status.NICE) {
+       if (s_theListCheckedOnce[msg.sender] == Status.NICE && s_theListCheckedTwice[msg.sender] == true) {    
            _mintAndIncrement();
            return;
        } 
-       else if (s_theListCheckedOnce[msg.sender] == Status.EXTRA_NICE && s_theListCheckedTwice[msg.sender] == Status.EXTRA_NICE)
+       else if (s_theListCheckedOnce[msg.sender] == Status.EXTRA_NICE && s_theListCheckedTwice[msg.sender] == true) 
        {
            _mintAndIncrement();
            i_santaToken.mint(msg.sender);
            return;
        }
        revert SantasList__NotNice();
    }
```

This ensures that `s_theListCheckedTwice[msg.sender]` is true only after `checkTwice()` has been successfully executed for that address.

## Informational

### [I-1] Unused `Status::NOT_CHECKED_TWICE` Enum Value and `PURCHASED_PRESENT_COST` Constant

**Description:** The contract defines the following enum:

```javascript
    enum Status {
        NICE,
        EXTRA_NICE,
        NAUGHTY,
@>      NOT_CHECKED_TWICE
    }
```
and the following constant:
```javascript
      // The cost of santa tokens for naughty people to buy presents
@>    uint256 public constant PURCHASED_PRESENT_COST = 2e18;
```

However, neither `Status::NOT_CHECKED_TWICE` nor `PURCHASED_PRESENT_COST` is used anywhere in the contract's logic.

The presence of these unused definitions suggests that functionality related to handling users who have not been checked twice and charging `2e18` SantaTokens for presents purchased by `NAUGHTY` users may have been intended but is not implemented.

**Impact:** This does not directly introduce a security vulnerability. However, unused definitions can indicate incomplete or missing protocol functionality and may cause the implementation to deviate from the intended business logic.

**Proof of Concept:**
The following definitions exist in the contract but have no references in the contract logic:

```javascript
enum Status {
    NICE,
    EXTRA_NICE,
    NAUGHTY,
    NOT_CHECKED_TWICE
}

// The cost of santa tokens for naughty people to buy presents
uint256 public constant PURCHASED_PRESENT_COST = 2e18;
```

**Recommended Mitigation:** 

If these definitions are part of the intended protocol design, implement the corresponding logic so that they affect the relevant status checks and present-purchasing behavior.

If they are not required by the final protocol design, remove the unused enum value and constant to avoid misleading developers and auditors about functionality that does not actually exist.