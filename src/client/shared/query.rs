use super::*;

pub trait QueryFilterTarget: Sized {
    fn push_filter<K: Into<String>, V: ToString>(
        self,
        field: K,
        op: FilterOperator,
        value: V,
    ) -> Self;

    fn push_raw_param<K: Into<String>, V: ToString>(self, key: K, value: V) -> Self;
}

#[derive(Debug, Clone)]
pub struct QueryValueField<Q, V> {
    pub(super) query: Q,
    pub(super) field: &'static str,
    pub(super) _phantom: PhantomData<V>,
}

impl<Q, V> QueryValueField<Q, V> {
    pub(crate) fn new(query: Q, field: &'static str) -> Self {
        Self {
            query,
            field,
            _phantom: PhantomData,
        }
    }
}

impl<Q: QueryFilterTarget, V: ToString> QueryValueField<Q, V> {
    pub fn eq(self, value: V) -> Q {
        self.query.push_filter(
            self.field,
            FilterOperator::Equals { is_negated: false },
            value,
        )
    }

    pub fn ne(self, value: V) -> Q {
        self.query.push_filter(
            self.field,
            FilterOperator::Equals { is_negated: true },
            value,
        )
    }
}

#[derive(Debug, Clone)]
pub struct QueryTextField<Q>(QueryValueField<Q, String>);

impl<Q> QueryTextField<Q> {
    pub(crate) fn new(query: Q, field: &'static str) -> Self {
        Self(QueryValueField::new(query, field))
    }
}

impl<Q: QueryFilterTarget> QueryTextField<Q> {
    pub fn eq(self, value: impl AsRef<str>) -> Q {
        self.0.eq(value.as_ref().to_string())
    }

    pub fn ne(self, value: impl AsRef<str>) -> Q {
        self.0.ne(value.as_ref().to_string())
    }

    pub fn ieq(self, value: impl AsRef<str>) -> Q {
        self.0.query.push_filter(
            self.0.field,
            FilterOperator::IEquals { is_negated: false },
            value.as_ref(),
        )
    }

    pub fn not_ieq(self, value: impl AsRef<str>) -> Q {
        self.0.query.push_filter(
            self.0.field,
            FilterOperator::IEquals { is_negated: true },
            value.as_ref(),
        )
    }

    pub fn contains(self, value: impl AsRef<str>) -> Q {
        self.0.query.push_filter(
            self.0.field,
            FilterOperator::Contains { is_negated: false },
            value.as_ref(),
        )
    }

    pub fn not_contains(self, value: impl AsRef<str>) -> Q {
        self.0.query.push_filter(
            self.0.field,
            FilterOperator::Contains { is_negated: true },
            value.as_ref(),
        )
    }

    pub fn icontains(self, value: impl AsRef<str>) -> Q {
        self.0.query.push_filter(
            self.0.field,
            FilterOperator::IContains { is_negated: false },
            value.as_ref(),
        )
    }

    pub fn not_icontains(self, value: impl AsRef<str>) -> Q {
        self.0.query.push_filter(
            self.0.field,
            FilterOperator::IContains { is_negated: true },
            value.as_ref(),
        )
    }

    pub fn starts_with(self, value: impl AsRef<str>) -> Q {
        self.0.query.push_filter(
            self.0.field,
            FilterOperator::StartsWith { is_negated: false },
            value.as_ref(),
        )
    }

    pub fn not_starts_with(self, value: impl AsRef<str>) -> Q {
        self.0.query.push_filter(
            self.0.field,
            FilterOperator::StartsWith { is_negated: true },
            value.as_ref(),
        )
    }

    pub fn istarts_with(self, value: impl AsRef<str>) -> Q {
        self.0.query.push_filter(
            self.0.field,
            FilterOperator::IStartsWith { is_negated: false },
            value.as_ref(),
        )
    }

    pub fn not_istarts_with(self, value: impl AsRef<str>) -> Q {
        self.0.query.push_filter(
            self.0.field,
            FilterOperator::IStartsWith { is_negated: true },
            value.as_ref(),
        )
    }

    pub fn ends_with(self, value: impl AsRef<str>) -> Q {
        self.0.query.push_filter(
            self.0.field,
            FilterOperator::EndsWith { is_negated: false },
            value.as_ref(),
        )
    }

    pub fn not_ends_with(self, value: impl AsRef<str>) -> Q {
        self.0.query.push_filter(
            self.0.field,
            FilterOperator::EndsWith { is_negated: true },
            value.as_ref(),
        )
    }

    pub fn iends_with(self, value: impl AsRef<str>) -> Q {
        self.0.query.push_filter(
            self.0.field,
            FilterOperator::IEndsWith { is_negated: false },
            value.as_ref(),
        )
    }

    pub fn not_iends_with(self, value: impl AsRef<str>) -> Q {
        self.0.query.push_filter(
            self.0.field,
            FilterOperator::IEndsWith { is_negated: true },
            value.as_ref(),
        )
    }

    pub fn like(self, value: impl AsRef<str>) -> Q {
        self.0.query.push_filter(
            self.0.field,
            FilterOperator::Like { is_negated: false },
            value.as_ref(),
        )
    }

    pub fn not_like(self, value: impl AsRef<str>) -> Q {
        self.0.query.push_filter(
            self.0.field,
            FilterOperator::Like { is_negated: true },
            value.as_ref(),
        )
    }

    pub fn regex(self, value: impl AsRef<str>) -> Q {
        self.0.query.push_filter(
            self.0.field,
            FilterOperator::Regex { is_negated: false },
            value.as_ref(),
        )
    }

    pub fn not_regex(self, value: impl AsRef<str>) -> Q {
        self.0.query.push_filter(
            self.0.field,
            FilterOperator::Regex { is_negated: true },
            value.as_ref(),
        )
    }
}

#[derive(Debug, Clone)]
pub struct QueryNumericField<Q, V>(QueryValueField<Q, V>);

impl<Q, V> QueryNumericField<Q, V> {
    pub(crate) fn new(query: Q, field: &'static str) -> Self {
        Self(QueryValueField::new(query, field))
    }
}

impl<Q: QueryFilterTarget, V: ToString> QueryNumericField<Q, V> {
    pub fn eq(self, value: V) -> Q {
        self.0.eq(value)
    }

    pub fn ne(self, value: V) -> Q {
        self.0.ne(value)
    }

    pub fn gt(self, value: V) -> Q {
        self.0.query.push_filter(
            self.0.field,
            FilterOperator::Gt { is_negated: false },
            value,
        )
    }

    pub fn gte(self, value: V) -> Q {
        self.0.query.push_filter(
            self.0.field,
            FilterOperator::Gte { is_negated: false },
            value,
        )
    }

    pub fn lt(self, value: V) -> Q {
        self.0.query.push_filter(
            self.0.field,
            FilterOperator::Lt { is_negated: false },
            value,
        )
    }

    pub fn lte(self, value: V) -> Q {
        self.0.query.push_filter(
            self.0.field,
            FilterOperator::Lte { is_negated: false },
            value,
        )
    }

    pub fn between(self, start: V, end: V) -> Q {
        self.0.query.push_filter(
            self.0.field,
            FilterOperator::Between { is_negated: false },
            format!("{},{}", start.to_string(), end.to_string()),
        )
    }
}

#[derive(Debug, Clone)]
pub struct QueryBoolField<Q>(QueryValueField<Q, bool>);

impl<Q> QueryBoolField<Q> {
    pub(crate) fn new(query: Q, field: &'static str) -> Self {
        Self(QueryValueField::new(query, field))
    }
}

impl<Q: QueryFilterTarget> QueryBoolField<Q> {
    pub fn eq(self, value: bool) -> Q {
        self.0.eq(value)
    }

    pub fn ne(self, value: bool) -> Q {
        self.0.ne(value)
    }
}

/// An unselected JSON-backed query field.
///
/// Select a validated, non-empty path before applying an operator. Hubuum
/// v0.0.9 does not define root-JSON filter syntax, so applying an operator
/// without a path records a local error returned by the terminal query method.
#[derive(Debug, Clone)]
pub struct QueryJsonField<Q> {
    pub(super) query: Q,
    pub(super) field: &'static str,
    pub(super) path: Option<Result<JsonPath, ()>>,
}

impl<Q> QueryJsonField<Q> {
    pub(crate) fn new(query: Q, field: &'static str) -> Self {
        Self {
            query,
            field,
            path: None,
        }
    }

    /// Select a JSON path, preserving the original fluent builder shape.
    ///
    /// The path is validated immediately and any error is returned by the
    /// terminal query operation before transport. Use [`Self::try_path`] when
    /// the caller needs the validation result at path-selection time.
    pub fn path<I, S>(mut self, path: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        self.path = Some(JsonPath::new(path).map_err(|_| ()));
        self
    }

    /// Validate and select a JSON path eagerly.
    pub fn try_path<I, S>(self, path: I) -> Result<QueryJsonPathField<Q>, ApiError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        Ok(self.with_path(JsonPath::new(path)?))
    }

    /// Select an already validated JSON path.
    pub fn with_path(self, path: JsonPath) -> QueryJsonPathField<Q> {
        QueryJsonPathField {
            query: self.query,
            field: self.field,
            path,
        }
    }
}

impl<Q: QueryFilterTarget> QueryJsonField<Q> {
    pub(super) fn push<V: ToString>(self, operator: FilterOperator, value: V) -> Q {
        let Self { query, field, path } = self;
        match path {
            Some(Ok(path)) => {
                query.push_filter(field, operator, format!("{path}={}", value.to_string()))
            }
            None | Some(Err(())) => query.push_raw_param(INVALID_JSON_PATH_QUERY_KEY, ""),
        }
    }

    pub fn eq<V: ToString>(self, value: V) -> Q {
        self.push(FilterOperator::Equals { is_negated: false }, value)
    }

    pub fn ne<V: ToString>(self, value: V) -> Q {
        self.push(FilterOperator::Equals { is_negated: true }, value)
    }

    pub fn gt<V: ToString>(self, value: V) -> Q {
        self.push(FilterOperator::Gt { is_negated: false }, value)
    }

    pub fn gte<V: ToString>(self, value: V) -> Q {
        self.push(FilterOperator::Gte { is_negated: false }, value)
    }

    pub fn lt<V: ToString>(self, value: V) -> Q {
        self.push(FilterOperator::Lt { is_negated: false }, value)
    }

    pub fn lte<V: ToString>(self, value: V) -> Q {
        self.push(FilterOperator::Lte { is_negated: false }, value)
    }

    pub fn between<V: ToString>(self, start: V, end: V) -> Q {
        self.push(
            FilterOperator::Between { is_negated: false },
            format!("{},{}", start.to_string(), end.to_string()),
        )
    }
}

/// A JSON-backed query field with a validated path selected.
#[derive(Debug, Clone)]
pub struct QueryJsonPathField<Q> {
    pub(super) query: Q,
    pub(super) field: &'static str,
    pub(super) path: JsonPath,
}

impl<Q: QueryFilterTarget> QueryJsonPathField<Q> {
    pub(super) fn encoded_value<V: ToString>(&self, value: V) -> String {
        format!("{}={}", self.path, value.to_string())
    }

    pub fn eq<V: ToString>(self, value: V) -> Q {
        let value = self.encoded_value(value);
        self.query.push_filter(
            self.field,
            FilterOperator::Equals { is_negated: false },
            value,
        )
    }

    pub fn ne<V: ToString>(self, value: V) -> Q {
        let value = self.encoded_value(value);
        self.query.push_filter(
            self.field,
            FilterOperator::Equals { is_negated: true },
            value,
        )
    }

    pub fn gt<V: ToString>(self, value: V) -> Q {
        let value = self.encoded_value(value);
        self.query
            .push_filter(self.field, FilterOperator::Gt { is_negated: false }, value)
    }

    pub fn gte<V: ToString>(self, value: V) -> Q {
        let value = self.encoded_value(value);
        self.query
            .push_filter(self.field, FilterOperator::Gte { is_negated: false }, value)
    }

    pub fn lt<V: ToString>(self, value: V) -> Q {
        let value = self.encoded_value(value);
        self.query
            .push_filter(self.field, FilterOperator::Lt { is_negated: false }, value)
    }

    pub fn lte<V: ToString>(self, value: V) -> Q {
        let value = self.encoded_value(value);
        self.query
            .push_filter(self.field, FilterOperator::Lte { is_negated: false }, value)
    }

    pub fn between<V: ToString>(self, start: V, end: V) -> Q {
        let value = self.encoded_value(format!("{},{}", start.to_string(), end.to_string()));
        self.query.push_filter(
            self.field,
            FilterOperator::Between { is_negated: false },
            value,
        )
    }
}
