use super::falcon_poly::{Poly, N, Q};

#[test]
fn test_poly_add_sub_neg() {
    let a = Poly::from_slice(&[1; N]);
    let b = Poly::from_slice(&[2; N]);
    let c = a.add(&b);
    assert_eq!(c.coeffs[0], 3);
    let d = c.sub(&a);
    assert_eq!(d.coeffs[0], 2);
    let e = d.neg();
    assert_eq!(e.coeffs[0], (Q as i32 - 2));
}
