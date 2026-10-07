use super::*;

#[test]
fn test_raw_towire_empty() {
    let result = raw_towire(2, &[]);
    assert_eq!(result, vec![2, 0, 0, 0, 0]);
}

#[test]
fn test_raw_towire_string() {
    let result = raw_towire(1, b"abc");
    assert_eq!(result, vec![1, 0, 0, 0, 3, 97, 98, 99]);
}

#[test]
fn test_binary_towire_empty() {
    let result = binary_towire("".as_bytes());
    assert_eq!(result, vec![1, 0, 0, 0, 0]);
}

#[test]
fn test_binary_towire_string() {
    let result = binary_towire("abc".as_bytes());
    assert_eq!(result, vec![1, 0, 0, 0, 3, 97, 98, 99]);
}

#[test]
fn test_list_towire_empty() {
    let result = list_towire(&[]);
    assert_eq!(result, vec![3, 0, 0, 0, 0]);
}

#[test]
fn test_list_towire_strings() {
    let values = vec![
        RNDCValue::Binary("abc".as_bytes().to_vec()),
        RNDCValue::Binary("ABC".as_bytes().to_vec()),
    ];
    let result = list_towire(&values);
    assert_eq!(
        result,
        vec![
            3, 0, 0, 0, 16, 1, 0, 0, 0, 3, 97, 98, 99, 1, 0, 0, 0, 3, 65, 66, 67,
        ]
    );
}

#[test]
fn test_table_towire_empty() {
    let result = table_towire(&IndexMap::new(), false);
    assert_eq!(result, vec![2, 0, 0, 0, 0]);
}

#[test]
fn test_table_towire_strings() {
    let mut map = IndexMap::new();
    map.insert(
        "K1".to_string(),
        RNDCValue::Binary("abc".as_bytes().to_vec()),
    );
    map.insert(
        "K2".to_string(),
        RNDCValue::Binary("ABC".as_bytes().to_vec()),
    );

    let result = table_towire(&map, false);
    assert_eq!(
        result,
        vec![
            2, 0, 0, 0, 22, 2, 75, 49, // "K1"
            1, 0, 0, 0, 3, 97, 98, 99, 2, 75, 50, // "K2"
            1, 0, 0, 0, 3, 65, 66, 67,
        ]
    );
}
