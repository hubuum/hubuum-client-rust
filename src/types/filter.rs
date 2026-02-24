use serde::{Deserialize, Serialize};

use crate::ApiError;

// FilterOperator enum
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub enum FilterOperator {
    Equals {
        is_negated: bool,
    },
    IEquals {
        is_negated: bool,
    },
    Contains {
        is_negated: bool,
    },
    IContains {
        is_negated: bool,
    },
    StartsWith {
        is_negated: bool,
    },
    IStartsWith {
        is_negated: bool,
    },
    EndsWith {
        is_negated: bool,
    },
    IEndsWith {
        is_negated: bool,
    },
    Like {
        is_negated: bool,
    },
    Regex {
        is_negated: bool,
    },
    Gt {
        is_negated: bool,
    },
    Gte {
        is_negated: bool,
    },
    Lt {
        is_negated: bool,
    },
    Lte {
        is_negated: bool,
    },
    Between {
        is_negated: bool,
    },
    /// Represents raw query parameters without an operator suffix, e.g. `sort=name.asc`.
    Raw,
}

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum DataType {
    String,
    NumericOrDate,
    Boolean,
    Array,
}

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum SortDirection {
    Asc,
    Desc,
}

impl std::fmt::Display for SortDirection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SortDirection::Asc => write!(f, "asc"),
            SortDirection::Desc => write!(f, "desc"),
        }
    }
}

impl FilterOperator {
    /// Checks if the operator is applicable to a given data type.
    pub fn is_applicable_to(&self, data_type: DataType) -> bool {
        type SO = FilterOperator;
        match self {
            SO::Equals { .. } => true,
            SO::Gt { .. }
            | SO::Gte { .. }
            | SO::Lt { .. }
            | SO::Lte { .. }
            | SO::Between { .. } => matches!(data_type, DataType::NumericOrDate),
            SO::Contains { .. } => {
                matches!(data_type, DataType::String) || matches!(data_type, DataType::Array)
            }
            SO::Raw => true,
            _ => {
                matches!(data_type, DataType::String)
            }
        }
    }
}

impl std::fmt::Display for FilterOperator {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            FilterOperator::Equals { is_negated } => {
                write!(f, "{}", if *is_negated { "not_equals" } else { "equals" })
            }
            FilterOperator::IEquals { is_negated } => write!(
                f,
                "{}",
                if *is_negated {
                    "not_iequals"
                } else {
                    "iequals"
                }
            ),
            FilterOperator::Contains { is_negated } => write!(
                f,
                "{}",
                if *is_negated {
                    "not_contains"
                } else {
                    "contains"
                }
            ),
            FilterOperator::IContains { is_negated } => write!(
                f,
                "{}",
                if *is_negated {
                    "not_icontains"
                } else {
                    "icontains"
                }
            ),
            FilterOperator::StartsWith { is_negated } => write!(
                f,
                "{}",
                if *is_negated {
                    "not_startswith"
                } else {
                    "startswith"
                }
            ),
            FilterOperator::IStartsWith { is_negated } => write!(
                f,
                "{}",
                if *is_negated {
                    "not_istartswith"
                } else {
                    "istartswith"
                }
            ),
            FilterOperator::EndsWith { is_negated } => write!(
                f,
                "{}",
                if *is_negated {
                    "not_endswith"
                } else {
                    "endswith"
                }
            ),
            FilterOperator::IEndsWith { is_negated } => write!(
                f,
                "{}",
                if *is_negated {
                    "not_iendswith"
                } else {
                    "iendswith"
                }
            ),
            FilterOperator::Like { is_negated } => {
                write!(f, "{}", if *is_negated { "not_like" } else { "like" })
            }
            FilterOperator::Regex { is_negated } => {
                write!(f, "{}", if *is_negated { "not_regex" } else { "regex" })
            }
            FilterOperator::Gt { is_negated } => {
                write!(f, "{}", if *is_negated { "not_gt" } else { "gt" })
            }
            FilterOperator::Gte { is_negated } => {
                write!(f, "{}", if *is_negated { "not_gte" } else { "gte" })
            }
            FilterOperator::Lt { is_negated } => {
                write!(f, "{}", if *is_negated { "not_lt" } else { "lt" })
            }
            FilterOperator::Lte { is_negated } => {
                write!(f, "{}", if *is_negated { "not_lte" } else { "lte" })
            }
            FilterOperator::Between { is_negated } => write!(
                f,
                "{}",
                if *is_negated {
                    "not_between"
                } else {
                    "between"
                }
            ),
            FilterOperator::Raw => write!(f, ""),
        }
    }
}

pub trait IntoQueryTuples {
    fn into_tuples(self) -> Vec<(String, String, String)>;
    fn into_query_string(self) -> Result<String, ApiError>;
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct QueryFilter {
    pub key: String,
    pub value: String,
    pub operator: FilterOperator,
}

impl std::fmt::Display for QueryFilter {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let operator = self.operator.to_string();
        if operator.is_empty() {
            write!(f, "{}={}", self.key, self.value)
        } else {
            write!(f, "{}__{}={}", self.key, operator, self.value)
        }
    }
}

impl QueryFilter {
    pub fn filter<K: Into<String>, V: Into<String>>(
        key: K,
        operator: FilterOperator,
        value: V,
    ) -> Self {
        Self {
            key: key.into(),
            value: value.into(),
            operator,
        }
    }

    pub fn raw<K: Into<String>, V: Into<String>>(key: K, value: V) -> Self {
        Self {
            key: key.into(),
            value: value.into(),
            operator: FilterOperator::Raw,
        }
    }

    pub fn as_query_tuple(&self) -> (String, String, String) {
        (
            self.key.clone(),
            self.operator.to_string(),
            self.value.clone(),
        )
    }
}

fn tuples_to_query_string(tuples: Vec<(String, String, String)>) -> Result<String, ApiError> {
    let params: Vec<(String, String)> = tuples
        .into_iter()
        .map(|(key, operator, value)| {
            if operator.is_empty() {
                (key, value)
            } else {
                (format!("{key}__{operator}"), value)
            }
        })
        .collect();

    serde_urlencoded::to_string(params).map_err(|err| ApiError::QueryEncoding(err.to_string()))
}

impl IntoQueryTuples for Vec<QueryFilter> {
    fn into_tuples(self) -> Vec<(String, String, String)> {
        self.iter().map(|filter| filter.as_query_tuple()).collect()
    }

    fn into_query_string(self) -> Result<String, ApiError> {
        tuples_to_query_string(self.into_tuples())
    }
}

impl IntoQueryTuples for &Vec<QueryFilter> {
    fn into_tuples(self) -> Vec<(String, String, String)> {
        self.iter().map(|filter| filter.as_query_tuple()).collect()
    }

    fn into_query_string(self) -> Result<String, ApiError> {
        tuples_to_query_string(self.into_tuples())
    }
}

impl IntoQueryTuples for &[QueryFilter] {
    fn into_tuples(self) -> Vec<(String, String, String)> {
        self.iter().map(|filter| filter.as_query_tuple()).collect()
    }

    fn into_query_string(self) -> Result<String, ApiError> {
        tuples_to_query_string(self.into_tuples())
    }
}

#[cfg(test)]
mod tests {
    use super::{FilterOperator, IntoQueryTuples, QueryFilter};

    #[test]
    fn filter_operator_display_includes_all_supported_operators() {
        let cases = [
            (FilterOperator::Equals { is_negated: false }, "equals"),
            (FilterOperator::Equals { is_negated: true }, "not_equals"),
            (FilterOperator::IEquals { is_negated: false }, "iequals"),
            (FilterOperator::IEquals { is_negated: true }, "not_iequals"),
            (FilterOperator::Contains { is_negated: false }, "contains"),
            (
                FilterOperator::Contains { is_negated: true },
                "not_contains",
            ),
            (FilterOperator::IContains { is_negated: false }, "icontains"),
            (
                FilterOperator::IContains { is_negated: true },
                "not_icontains",
            ),
            (
                FilterOperator::StartsWith { is_negated: false },
                "startswith",
            ),
            (
                FilterOperator::StartsWith { is_negated: true },
                "not_startswith",
            ),
            (
                FilterOperator::IStartsWith { is_negated: false },
                "istartswith",
            ),
            (
                FilterOperator::IStartsWith { is_negated: true },
                "not_istartswith",
            ),
            (FilterOperator::EndsWith { is_negated: false }, "endswith"),
            (
                FilterOperator::EndsWith { is_negated: true },
                "not_endswith",
            ),
            (FilterOperator::IEndsWith { is_negated: false }, "iendswith"),
            (
                FilterOperator::IEndsWith { is_negated: true },
                "not_iendswith",
            ),
            (FilterOperator::Like { is_negated: false }, "like"),
            (FilterOperator::Like { is_negated: true }, "not_like"),
            (FilterOperator::Regex { is_negated: false }, "regex"),
            (FilterOperator::Regex { is_negated: true }, "not_regex"),
            (FilterOperator::Gt { is_negated: false }, "gt"),
            (FilterOperator::Gt { is_negated: true }, "not_gt"),
            (FilterOperator::Gte { is_negated: false }, "gte"),
            (FilterOperator::Gte { is_negated: true }, "not_gte"),
            (FilterOperator::Lt { is_negated: false }, "lt"),
            (FilterOperator::Lt { is_negated: true }, "not_lt"),
            (FilterOperator::Lte { is_negated: false }, "lte"),
            (FilterOperator::Lte { is_negated: true }, "not_lte"),
            (FilterOperator::Between { is_negated: false }, "between"),
            (FilterOperator::Between { is_negated: true }, "not_between"),
            (FilterOperator::Raw, ""),
        ];

        for (operator, expected) in cases {
            assert_eq!(operator.to_string(), expected);
        }
    }

    #[test]
    fn into_query_string_encodes_reserved_characters() {
        let filters = vec![QueryFilter {
            key: "name".to_string(),
            value: "A&B = C/D?".to_string(),
            operator: FilterOperator::Equals { is_negated: false },
        }];

        let got = filters.into_query_string();
        assert!(got.is_ok());
        assert_eq!(
            got.unwrap_or_default(),
            "name__equals=A%26B+%3D+C%2FD%3F".to_string()
        );
    }

    #[test]
    fn into_query_string_is_consistent_across_vec_and_slice() {
        let filters = vec![
            QueryFilter {
                key: "name".to_string(),
                value: "alpha beta".to_string(),
                operator: FilterOperator::Equals { is_negated: false },
            },
            QueryFilter {
                key: "description".to_string(),
                value: "x&y".to_string(),
                operator: FilterOperator::Contains { is_negated: false },
            },
        ];

        let expected = "name__equals=alpha+beta&description__contains=x%26y";
        let from_vec = filters.clone().into_query_string();
        let from_ref_vec = (&filters).into_query_string();
        let from_slice = filters.as_slice().into_query_string();

        assert!(from_vec.is_ok());
        assert!(from_ref_vec.is_ok());
        assert!(from_slice.is_ok());
        assert_eq!(from_vec.unwrap_or_default(), expected.to_string());
        assert_eq!(from_ref_vec.unwrap_or_default(), expected.to_string());
        assert_eq!(from_slice.unwrap_or_default(), expected.to_string());
    }

    #[test]
    fn into_query_string_supports_raw_query_parameters() {
        let filters = vec![
            QueryFilter::raw("sort", "name.asc,created_at.desc"),
            QueryFilter::raw("limit", "10"),
        ];

        let got = filters.into_query_string();
        assert!(got.is_ok());
        assert_eq!(
            got.unwrap_or_default(),
            "sort=name.asc%2Ccreated_at.desc&limit=10".to_string()
        );
    }
}
