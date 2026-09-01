
#[derive(Debug)]
enum E { A(String) }
fn main() {
    let e = E::A("hello".to_owned());
    assert!(matches!(e, E::A(s) if s == "hello"), "got {e:?}", e);
    println!("ok");
}
