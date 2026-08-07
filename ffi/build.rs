fn main() {
    uniffi::generate_scaffolding("src/rooms.udl").expect("UDL scaffolding");
}
