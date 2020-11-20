module Requirements where

-- TODO: how to capture password requirements and generate passwords satifying these requirements?
-- Requirements:
-- at least 8 characters in length
-- printable ASCII characters, space character, and Unicode characters should be accepted
-- password strength meter???
-- passwords should be salted before being hashed and stored
-- Example requirements:
-- Must contain
-- - A lowercase character
-- - An uppercase character
-- - A number
-- - A special character
import Data.Char (ord)
import Types

data EntropyLevel
    = Low
    | High
    deriving (Eq, Ord, Show)

entropy :: Password -> EntropyLevel
entropy p =
    if any (\diff -> sum (map abs diff) < 250)
           [diffs 0 p, diffs 1 p, diffs 2 p, diffs 3 p, diffs 4 p, diffs 5 p]
        then Low
        else High

entropy' :: (a -> Int) -> [a] -> Int -> Int -> Int
entropy' _ [] _ acc = acc
entropy' v (h:t) n acc = entropy' v t (v h) $ acc + abs (n - vh)
  where
    vh = v h

differences :: [Int] -> [Int]
differences [] = []
differences l = tail $ differences' (head l) l
  where
    differences' :: Int -> [Int] -> [Int]
    differences' _ [] = []
    differences' n (h:t) = h - n : differences' h t

diffs' :: (a -> Int) -> Int -> [a] -> [Int]
diffs' v 0 = map v
diffs' v n = differences . diffs' v (n - 1)

diffs :: Int -> Password -> [Int]
diffs = diffs' ord
