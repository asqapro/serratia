class IAttack {
 public:
  virtual void run() = 0;
  virtual ~IAttack() = default;
};