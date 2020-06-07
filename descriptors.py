#!/usr/bin/env python3
from __future__ import annotations

from collections import deque
from typing import List, Optional, Tuple

from bip32 import BIP32, HARDENED_INDEX

from scripts import ScriptType

# m: master key
# a: account index
# i: address index
descriptors = {
    "m/44'/0'/a'/0/i": [ScriptType.LEGACY],  # BIP44, external
    "m/44'/0'/a'/1/i": [ScriptType.LEGACY],  # BIP44, change
    "m/49'/0'/a'/0/i": [ScriptType.COMPAT],  # BIP49, external
    "m/49'/0'/a'/1/i": [ScriptType.COMPAT],  # BIP49, change
    "m/84'/0'/a'/0/i": [ScriptType.SEGWIT],  # BIP84, external
    "m/84'/0'/a'/1/i": [ScriptType.SEGWIT],  # BIP84, change
    "m/0'/0'/i'": [ScriptType.LEGACY, ScriptType.COMPAT, ScriptType.SEGWIT],  # Bitcoin Core
    "m/0'/0/i": [ScriptType.LEGACY, ScriptType.COMPAT, ScriptType.SEGWIT],  # BRD/Hodl/Coin/Multibit external
    "m/0'/1/i": [ScriptType.LEGACY, ScriptType.COMPAT, ScriptType.SEGWIT],  # BRD/Hodl/Coin/Multibit change
    "m/44'/0'/2147483647'/0/i": [ScriptType.LEGACY],  # Samourai ricochet, BIP44, external
    "m/44'/0'/2147483647'/1/i": [ScriptType.LEGACY],  # Samourai ricochet, BIP44, change
    "m/49'/0'/2147483647'/0/i": [ScriptType.COMPAT],  # Samourai ricochet, BIP49, external
    "m/49'/0'/2147483647'/1/i": [ScriptType.COMPAT],  # Samourai ricochet, BIP49, change
    "m/84'/0'/2147483647'/0/i": [ScriptType.SEGWIT],  # Samourai ricochet, BIP84, external
    "m/84'/0'/2147483647'/1/i": [ScriptType.SEGWIT],  # Samourai ricochet, BIP84, change
    "m/84'/0'/2147483646'/0/i": [ScriptType.SEGWIT],  # Samourai post-mix, external
    "m/84'/0'/2147483646'/1/i": [ScriptType.SEGWIT],  # Samourai post-mix, change
    "m/84'/0'/2147483645'/0/i": [ScriptType.SEGWIT],  # Samourai pre-mix, external
    "m/84'/0'/2147483645'/1/i": [ScriptType.SEGWIT],  # Samourai pre-mix, change
    "m/84'/0'/2147483644'/0/i": [ScriptType.SEGWIT],  # Samourai bad-bank, external
    "m/84'/0'/2147483644'/1/i": [ScriptType.SEGWIT],  # Samourai bad-bank, change
}


class Path:
    """
    Derivation path from a master key that may have a variable account number, and a variable index number.
    """

    def __init__(self, path: str):
        self.path = path

    def has_variable_account(self) -> bool:
        """
        Whether this path has the account level as a free variable.
        """
        return self.path.find('a') >= 0

    def has_variable_index(self) -> bool:
        """
        Whether this path has the index level as a free variable.
        """
        return self.path.find('i') >= 0

    def to_list(self, index: int = None, account: int = None) -> List[int]:
        """
        Transform this path into a list of valid derivation indexes.
        """
        # replace the placeholders
        path = self.path.replace('a', str(account)).replace('i', str(index))
        parts = path.split('/')[1:]

        # compute the derivation indexes
        indexes = []
        for part in parts:
            if part.endswith("'"):
                indexes.append(HARDENED_INDEX + int(part[:-1]))
            else:
                indexes.append(int(part))
        return indexes

    def with_account(self, account: int) -> Path:
        """
        Get a new path with a fixed account.
        """
        return Path(self.path.replace('a', str(account)))

    def with_index(self, index: int) -> Path:
        """
        Get a new path with a fixed index.
        """
        return Path(self.path.replace('i', str(index)))

    def __eq__(self, other):
        if isinstance(other, Path):
            return self.path == other.path
        return NotImplemented

    def __hash__(self):
        return hash(self.path)


class DescriptorScriptIterator:
    """
    Iterator that can traverse the all the possible scripts generated by a descriptor (ie. a path and script type pair).
    """

    def __init__(self, path: Path, script_type: ScriptType, address_gap: int, account_gap: int):
        self.path = path
        self.script_type = script_type
        self.address_gap = address_gap
        self.account_gap = account_gap
        self.index = 0
        self.account = 0
        self.max_index = address_gap if path.has_variable_index() else 0
        self.max_account = account_gap if path.has_variable_account() else 0
        self.extra_indices = deque()
        self.extra_accounts = deque()
        self.total_scripts = (self.max_index + 1) * (self.max_account + 1)

    def _script_at(self, master_key: BIP32, index: int, account: int) -> Tuple[bytes, Path, int, ScriptType]:
        """
        Render the script at a specific index and account.
        """
        path = self.path.with_account(account)
        pubkey = master_key.get_pubkey_from_path(path.to_list(index))
        script = self.script_type.build_output_script(pubkey)

        return script, path, index, self.script_type

    def next_script(self, master_key: BIP32) -> Optional[Tuple[bytes, Path, int, ScriptType]]:
        """
        Fetch the next script for the current descriptor.
        """
        if self.extra_indices:
            index, account = self.extra_indices.popleft()
            return self._script_at(master_key, index, account)

        if self.extra_accounts:
            index, account = self.extra_accounts.popleft()
            return self._script_at(master_key, index, account)

        if self.index > self.max_index or self.account > self.max_account:
            return None

        response = self._script_at(master_key, self.index, self.account)

        self.last_index = self.index
        self.last_account = self.account

        # Since traversing the entire [0; MAX_INDEX] x [0; MAX_ACCOUNT] space of combinations might take a while, we
        # walk the (index, account) grid in diagonal order. This order prioritizes the most probable combinations
        # (ie. low index, low account), while letting us explore a large space in the long run.
        #
        #           0     1     2
        #         ↙     ↙     ↙
        #    (0,0) (1,0) (2,0)  3
        #   ↙     ↙     ↙     ↙
        #    (0,1) (1,1) (2,1)  4
        #   ↙     ↙     ↙     ↙
        #    (0,2) (1,2) (2,2)  5
        #   ↙     ↙     ↙     ↙
        #    (0,3) (1,3) (2,3)
        #   ↙     ↙     ↙

        if self.index == 0 or self.account == self.max_account:
            # if we reached the border, start in the next diagonal
            diagonal_total = self.index + self.account + 1
            self.index = min(diagonal_total, self.max_index)
            self.account = diagonal_total - self.index
        else:
            # go down the diagonal
            self.index -= 1
            self.account += 1

        return response

    def found_used_script(self) -> None:
        """
        Update the next scripts to process knowing that the last script was used.
        """
        # explore enough indices in the same account to make sure we cover the address gap
        for i in range(self.last_index + 1, self.last_index + self.address_gap + 1):
            # TODO: this will be slow for large address gap limits
            if i > self.max_index and (i, self.last_account) not in self.extra_indices:
                self.extra_indices.append((i, self.account))
                self.total_scripts += 1

        # explore enough accounts to make sure we cover the account gap
        while self.max_account <= self.last_account + self.account_gap:
            self.max_account += 1
            self.total_scripts += self.max_index + 1
            current_diagonal = self.index + self.account
            for i in range(current_diagonal - self.max_account):
                self.extra_accounts.append((i, self.max_account))

    def has_priority_scripts(self) -> bool:
        """
        Whether this descriptor should be prioritized because its exploring a used account path.
        """
        return bool(self.extra_indices)


class ScriptIterator:
    """
    Iterator that can traverse all the possible scripts of all the possible descriptors.
    """

    def __init__(self, master_key: BIP32, address_gap: int, account_gap: int):
        self.master_key = master_key
        self.index = 0
        self.descriptors = []
        self.last_descriptor = None
        for path, types in descriptors.items():
            for type in types:
                self.descriptors.append(DescriptorScriptIterator(Path(path), type, address_gap, account_gap))

    def _next_descriptor_script(self) -> Optional[Tuple[bytes, Path, int, ScriptType]]:
        """
        Fetch the next script from the next descriptor. If the descriptor doesn't have a next script, remove it.
        """
        if self.last_descriptor and self.last_descriptor.has_priority_scripts():
            iter = self.last_descriptor.next_script(self.master_key)
            if iter:
                return iter

        self.last_descriptor = self.descriptors[self.index]
        iter = self.last_descriptor.next_script(self.master_key)

        if not iter:
            del self.descriptors[self.index]
            self.index -= 1

        self.index += 1
        if self.index >= len(self.descriptors):
            self.index = 0

        return iter

    def next_script(self) -> Optional[Tuple[bytes, Path, int, ScriptType]]:
        """
        Fetch the next script, cycling the descriptors in order to explore all of them progressively.
        """
        while len(self.descriptors) > 0:
            iter = self._next_descriptor_script()
            if iter:
                return iter

        return None

    def total_scripts(self) -> int:
        """
        Compute the total number of scripts that were or will be explored.
        """
        return sum([d.total_scripts for d in self.descriptors])

    def found_used_script(self) -> None:
        """
        Update the next scripts to process knowing that the last script was used.
        """
        self.last_descriptor.found_used_script()
