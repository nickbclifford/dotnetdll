use super::Rule;
use pest::iterators::{Pair, Pairs};

pub trait Combinators {
    fn maybe<T>(&mut self, target: Rule, body: impl FnOnce(Pair<Rule>) -> T) -> Option<T>;
    fn many0<T>(&mut self, target: Rule, body: impl FnMut(Pair<Rule>) -> T) -> Vec<T>;
}

impl Combinators for Pairs<'_, Rule> {
    fn maybe<T>(&mut self, target: Rule, body: impl FnOnce(Pair<Rule>) -> T) -> Option<T> {
        self.peek().and_then(|p| {
            if p.as_rule() == target {
                Some(body(self.next().unwrap()))
            } else {
                None
            }
        })
    }

    fn many0<T>(&mut self, target: Rule, body: impl FnMut(Pair<Rule>) -> T) -> Vec<T> {
        let mut result = vec![];
        while let Some(next) = self.peek() {
            if next.as_rule() == target {
                result.push(body(self.next().unwrap()));
            } else {
                break;
            }
        }
        result
    }
}
